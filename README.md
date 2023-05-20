# Issue H-1: Deadline check is not effective, allowing outdated slippage and allow pending transaction to be unexpected executed 

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/145 

## Found by 
Bauer, Breeje, ctf\_sec

## Summary

Deadline check is not effective, allowing outdated slippage and allow pending transaction to be unexpected executed

## Vulnerability Detail

In the current implementation in CurveSpell.sol

```solidity
{
	// 2. Swap rewards tokens to debt token
	uint256 rewards = _doCutRewardsFee(CRV);
	_ensureApprove(CRV, address(swapRouter), rewards);
	swapRouter.swapExactTokensForTokens(
		rewards,
		0,
		swapPath,
		address(this),
		type(uint256).max
	);
}
```

the deadline check is set to type(uint256).max, which means the deadline check is disabled!

In IChiSpell. the swap is directedly call on the pool instead of the router

```solidity
SWAP_POOL.swap(
	address(this),
	// if withdraw token is Token0, then swap token1 -> token0 (false)
	!isTokenA,
	amountToSwap.toInt256(),
	isTokenA
		? param.sqrtRatioLimit + deltaSqrt
		: param.sqrtRatioLimit - deltaSqrt, // slippaged price cap
	abi.encode(address(this))
);
```

and it has no deadline check for the transaction when swapping

## Impact

AMMs provide their users with an option to limit the execution of their pending actions, such as swaps or adding and removing liquidity. The most common solution is to include a deadline timestamp as a parameter (for example see Uniswap V2 and Uniswap V3). If such an option is not present, users can unknowingly perform bad trades:

Alice wants to swap 100 tokens for 1 ETH and later sell the 1 ETH for 1000 DAI.

The transaction is submitted to the mempool, however, Alice chose a transaction fee that is too low for miners to be interested in including her transaction in a block. The transaction stays pending in the mempool for extended periods, which could be hours, days, weeks, or even longer.

When the average gas fee dropped far enough for Alice's transaction to become interesting again for miners to include it, her swap will be executed. In the meantime, the price of ETH could have drastically changed. She will still get 1 ETH but the DAI value of that output might be significantly lower. 

She has unknowingly performed a bad trade due to the pending transaction she forgot about.

An even worse way this issue can be maliciously exploited is through MEV:

The swap transaction is still pending in the mempool. Average fees are still too high for miners to be interested in it. 

The price of tokens has gone up significantly since the transaction was signed, meaning Alice would receive a lot more ETH when the swap is executed. But that also means that her maximum slippage value (sqrtPriceLimitX96 and minOut in terms of the Spell contracts) is outdated and would allow for significant slippage.

A MEV bot detects the pending transaction. Since the outdated maximum slippage value now allows for high slippage, the bot sandwiches Alice, resulting in significant profit for the bot and significant loss for Alice.

## Code Snippet

https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/CurveSpell.sol#L162-L175

## Tool used

Manual Review

## Recommendation

We recommend the protocol use block.timstamp for swapping deadline for Uniswap V2 and swap with Unsiwap Router V3 instead of the pool directly!

# Issue H-2: `BalancerPairOracle` can be manipulated using read-only reentrancy 

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/141 

## Found by 
cuthalion0x

## Summary

`BalancerPairOracle.getPrice` makes an external call to `BalancerVault.getPoolTokens` without checking the Balancer Vault's reentrancy guard. As a result, the oracle can be trivially manipulated to liquidate user positions prematurely.

## Vulnerability Detail

In February, the Balancer team disclosed a read-only reentrancy vulnerability in the Balancer Vault. The detailed disclosure can be found [here](https://forum.balancer.fi/t/reentrancy-vulnerability-scope-expanded/4345). In short, all Balancer pools are susceptible to manipulation of their external queries, and all integrations must now take an extra step of precaution when consuming data. Via reentrancy, an attacker can force token balances and BPT supply to be out of sync, creating very inaccurate BPT prices.

Some protocols, such as Sentiment, remained unaware of this issue for a few months and were later [hacked](https://twitter.com/spreekaway/status/1643313471180644360) as a result.

`BalancerPairOracle.getPrice` makes a price calculation of the form `f(balances) / pool.totalSupply()`, so it is clearly vulnerable to synchronization issues between the two data points. A rough outline of the attack might look like this:

```solidity
AttackerContract.flashLoan() ->
    // Borrow lots of tokens and trigger a callback.
    SomeProtocol.flashLoan() ->
        AttackerContract.exploit()

AttackerContract.exploit() ->
    // Join a Balancer Pool using the borrowed tokens and send some ETH along with the call.
    BalancerVault.joinPool() ->
        // The Vault will return the excess ETH to the sender, which will reenter this contract.
        // At this point in the execution, the BPT supply has been updated but the token balances have not.
        AttackerContract.receive()

AttackerContract.receive() ->
    // Liquidate a position using the same Balancer Pool as collateral.
    BlueBerryBank.liquidate() ->
        // Call to the oracle to check the price.
        BalancerPairOracle.getPrice() ->
            // Query the token balances. At this point in the execution, these have not been updated (see above).
            // So, the balances are still the same as before the start of the large pool join.
            BalancerVaul.getPoolTokens()

            // Query the BPT supply. At this point in the execution, the supply has already been updated (see above).
            // So, it includes the latest large pool join, and as such the BPT supply has grown by a large amount.
            BalancerPool.getTotalSupply()

            // Now the price is computed using both balances and supply, and the result is much smaller than it should be.
            price = f(balances) / pool.totalSupply()

        // The position is liquidated under false pretenses.
```

## Impact

Users choosing Balancer pool positions (such as Aura vaults) as collateral can be prematurely liquidated due to unreliable price data.

## Code Snippet

https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/oracle/BalancerPairOracle.sol#L70-L92

## Tool used

Manual Review

## Recommendation

The Balancer team recommends utilizing their [official library](https://github.com/balancer/balancer-v2-monorepo/blob/3ce5138abd8e336f9caf4d651184186fffcd2025/pkg/pool-utils/contracts/lib/VaultReentrancyLib.sol) to safeguard queries such as `Vault.getPoolTokens`. However, the library makes a state-modifying call to the Balancer Vault, so it is not suitable for `view` functions such as `BalancerPairOracle.getPrice`. There are then two options:
1. Invoke the library somewhere else. Perhaps insert a hook into critical system functions like `BlueBerryBank.liquidate`.
2. Adapt a slightly different read-only solution that checks the Balancer Vault's reentrancy guard without actually entering.

# Issue H-3: WIchiFarm#pendingRewards suffers from significant precision loss causing loss of rewards 

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/137 

## Found by 
0x52

## Summary

IchI LPs are 18 dp tokens while IchiPerShare is only 9 dp. In conjunction with how small typical Ichi LP values are, the precision loss caused during calculation can cause nontrivial loss to users. 

## Vulnerability Detail

[WIchiFarm.sol#L122-L127](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/wrapper/WIchiFarm.sol#L122-L127)

        (uint256 enIchiPerShare, , ) = ichiFarm.poolInfo(pid);
        uint256 stIchi = (stIchiPerShare * amount).divCeil(10 ** lpDecimals);
        uint256 enIchi = (enIchiPerShare * amount) / (10 ** lpDecimals); <- @audit-issue precision loss here
        uint256 ichiRewards = enIchi > stIchi ? enIchi - stIchi : 0;
        // Convert rewards to ICHI(v2) => ICHI v1 decimal: 9, ICHI v2 Decimal: 18
        ichiRewards *= 1e9;

Since stIchi and enIchi are calculated separate from eachother, it results in precision loss. Normally this precision loss would result in trivial losses but in these circumstances the losses could be quite large. This is because IchiPerShare is stored as a 9 dp value. Additionally even large deposits result in [very low LP values](https://etherscan.io/tx/0xe6acb00276123aae88698476e724b59e61f16ce3b7ffac23bdbedf4578a0b23d). This creates a scenario where users can lose substantial rewards to precision loss.

Example:
A user deposits $500 worth of ICHI to get ICHI LP. This deposit results in the user receiving ~860000000 LP (based on current conditions). Now imagine a the IchiPerShare increases by 1e9 (1 unit of IchIV1). Based on the current math this would result in the user getting 0 in rewards:

860000000 * 1e9 / 1e18 = 0.86 which is truncated to 0.

## Impact

Precision loss will cause permanent loss to the user

## Code Snippet

[WIchiFarm.sol#L110-L133](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/wrapper/WIchiFarm.sol#L110-L133)

## Tool used

Manual Review

## Recommendation

Calculate rewards like [WConvexPools](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/wrapper/WConvexPools.sol#L110-L121) to reduce precision loss as much as possible.



## Discussion

**bwafflef**

@sherlock-admin @Gornutz 
I think the logic of `pendingRewards` function in `WIchiFarm.sol` contract is accurate and there is no loss of rewards.
For this, we need to have a look at `accShare` logic of `IchiFarm` contract. `accShare` is the variable represents `rewards per input amount(lp)`. Reward token of `IchiFarm` contract is `ICHI(v1)` token which it's decimal is 9, so both of `stIchi` and `enIchi` has 9 decimals (the same as `ICHI(v1)` token's decimal). This `ICHI(v1)` token is converted to `ICHI(v2)` token  which has 18 decimals, and distributed to users in `burn` function (https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/wrapper/WIchiFarm.sol#L177-L180)

For this case ( `860000000 * 1e9 / 1e18 = 0.86 which is truncated to 0` ), reward is calculated as 0 not only on our side but also `IchiFarm` contract side and there is no loss of rewards. Let me know if you still have some questions.

**IAm0x52**

Your comment would be true if a single user made up the entire pool. However the pool is an aggregate of many users that all earn rewards as a whole (all LP deposited to the same address). It would be true that each user may not accumulate more than the minimum individually but as a collective they would exceed it and therefore should be due their fair share.

**bwafflef**

> Your comment would be true if a single user made up the entire pool. However the pool is an aggregate of many users that all earn rewards as a whole (all LP deposited to the same address). It would be true that each user may not accumulate more than the minimum individually but as a collective they would exceed it and therefore should be due their fair share.

It seems like your suggestion might be correct, but it will never happen that `as a collective they would exceed it and therefore should be due fair share`. Is there any case this happens? The `example` in the above is not the case for this.

**IAm0x52**

If there are two users and they deposit 500000000 LP each. Each user will be due:

`500000000 * 1e9 / 1e18 = 0.5 => 0`

Together there will be 1000000000 LP so as a whole they will earn from the ICHI farm:

`1000000000 * 1e9 / 1e18 = 1`

If each user were to deposit independently, neither would receive a reward form the farm (both truncate to 0) but when put in together they earn 1 which isn't truncated. Therefore in that case both users should be due their fair share 

**bwafflef**

@IAm0x52  i get your point, but reward loss in this case is 0.5 wei, which is quite small. I'm not sure about the solution to handle this kind of minor amount smaller than 1 wei. Do you have any suggestion?

**bwafflef**

Also the important point we need to consider here is that reward calc logic in `pendingRewards` function is the same in `IchiFarm` contract following masterChef contract logic. This means there is a loss of 0.5 wei ICHI(reward) when we claim ICHI reward from `IchiFarm` contract.

# Issue H-4: Pending CRV rewards are not accounted for and can cause unfair liquidations 

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/136 

## Found by 
0x52

## Summary

pendingRewards are factored into the health of a position so that the position collateral is fairly assessed. However WCurveGauge#pendingRewards doesn't return the proper reward tokens/amounts meaning that positions aren't valued correctly and users can be unfairly liquidated.

## Vulnerability Detail

[BlueBerryBank.sol#L408-L413](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/BlueBerryBank.sol#L408-L413)

            (address[] memory tokens, uint256[] memory rewards) = IERC20Wrapper(
                pos.collToken
            ).pendingRewards(pos.collId, pos.collateralSize);
            for (uint256 i; i < tokens.length; i++) {
                rewardsValue += oracle.getTokenValue(tokens[i], rewards[i]);
            }

When BlueBerryBank is valuing a position it also values the pending rewards since they also have value. 

[WCurveGauge.sol#L106-L114](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/wrapper/WCurveGauge.sol#L106-L114)

    function pendingRewards(
        uint256 tokenId,
        uint256 amount
    )
        public
        view
        override
        returns (address[] memory tokens, uint256[] memory rewards)
    {}

Above we see that WCurveGauge#pendingRewards returns empty arrays when called. This means that pending rewards are not factored in correctly and users can be liquidated when even when they should be safe.

## Impact

User is liquidated when they shouldn't be

## Code Snippet

[WCurveGauge.sol#L106-L114](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/wrapper/WCurveGauge.sol#L106-L114)

## Tool used

Manual Review

## Recommendation

Change WCurveGauge#pendingRewards to correctly return the pending rewards

# Issue H-5: ShortLongSpell#openPosition can cause user unexpected liquidation when increasing position size 

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/135 

## Found by 
0x52, Ch\_301

## Summary

When increasing a position, all collateral is sent to the user rather than being kept in the position. This can cause serious issues because this collateral keeps the user from being liquidated. It may unexpectedly leave the user on the brink of liquidation where a small change in price leads to their liquidation.

## Vulnerability Detail

[ShortLongSpell.sol#L129-L141](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/ShortLongSpell.sol#L129-L141)

        {
            IBank.Position memory pos = bank.getCurrentPositionInfo();
            address posCollToken = pos.collToken;
            uint256 collSize = pos.collateralSize;
            address burnToken = address(ISoftVault(strategy.vault).uToken());
            if (collSize > 0) {
                if (posCollToken != address(wrapper))
                    revert Errors.INCORRECT_COLTOKEN(posCollToken);
                bank.takeCollateral(collSize);
                wrapper.burn(burnToken, collSize);
                _doRefund(burnToken);
            }
        }

In the above lines we can see that all collateral is burned and the user is sent the underlying tokens. This is problematic as it sends all the collateral to the user, leaving the position collateralized by only the isolated collateral.

Best case the user's transaction reverts but worst case they will be liquidated almost immediately.  

## Impact

Unfair liquidation for users

## Code Snippet

[ShortLongSpell.sol#L111-L151](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/ShortLongSpell.sol#L111-L151)

## Tool used

Manual Review

## Recommendation

Don't burn the collateral

# Issue H-6: Balance check for swapToken in ShortLongSpell#_deposit is incorrect and will result in nonfunctional contract 

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/133 

## Found by 
0x52, Ch\_301, sinarette

## Summary

The balance checks on ShortLongSpell#_withdraw are incorrect and will make contract basically nonfunctional 

## Vulnerability Detail

swapToken is always vault.uToken. borrowToken is always required to be vault.uToken which means that swapToken == borrowToken. This means that the token borrowed is always required to be swapped. 

[ShortLongSpell.sol#L83-L89](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/ShortLongSpell.sol#L83-L89)

        uint256 strTokenAmt = _doBorrow(param.borrowToken, param.borrowAmount);

        // 3. Swap borrowed token to strategy token
        IERC20Upgradeable swapToken = ISoftVault(strategy.vault).uToken();
        // swapData.fromAmount = strTokenAmt;
        PSwapLib.megaSwap(augustusSwapper, tokenTransferProxy, swapData);
        strTokenAmt = swapToken.balanceOf(address(this)) - strTokenAmt; <- @audit-issue will always revert on swap

Because swapToken == borrowToken if there is ever a swap then the swapToken balance will decrease. This causes L89 to always revert when a swap happens, making the contract completely non-functional

## Impact

ShortLongSpell is nonfunctional

## Code Snippet

[ShortLongSpell.sol#L160-L202](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/ShortLongSpell.sol#L160-L202)

## Tool used

Manual Review

## Recommendation

Remove check

# Issue H-7: UniswapV3 sqrtRatioLimit doesn't provide slippage protection and will result in partial swaps 

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/132 

## Found by 
0x52

## Summary

The sqrtRatioLimit for UniV3 doesn't cause the swap to revert upon reaching that value. Instead it just cause the swap to partially fill. This is a [known issue](https://github.com/Uniswap/v3-core/blob/d8b1c635c275d2a9450bd6a78f3fa2484fef73eb/contracts/UniswapV3Pool.sol#L641) with using sqrtRatioLimit as can be seen here where the swap ends prematurely when it has been reached. This is problematic as this is meant to provide the user with slippage protection but doesn't.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/IchiSpell.sol#L209-L223

        if (amountToSwap > 0) {
            SWAP_POOL = IUniswapV3Pool(vault.pool());
            uint160 deltaSqrt = (param.sqrtRatioLimit *
                uint160(param.sellSlippage)) / uint160(Constants.DENOMINATOR);
            SWAP_POOL.swap(
                address(this),
                // if withdraw token is Token0, then swap token1 -> token0 (false)
                !isTokenA,
                amountToSwap.toInt256(),
                isTokenA
                    ? param.sqrtRatioLimit + deltaSqrt
                    : param.sqrtRatioLimit - deltaSqrt, // slippaged price cap
                abi.encode(address(this))
            );
        }

sqrtRatioLimit is used as slippage protection for the user but is ineffective and depending on what tokens are being swapped, tokens may be left the in the contract which can be stolen by anyone.

## Impact

Incorrect slippage application can result in partial swaps and loss of funds

## Code Snippet

[IchiSpell.sol#L181-L236](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/IchiSpell.sol#L181-L236)

## Tool used

Manual Review

## Recommendation

Check the amount received from the swap and compare it against some user supplied minimum

# Issue H-8: UserData for balancer pool exits is malformed and will permanently trap users 

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/129 

## Found by 
0x52, cuthalion0x

## Summary

UserData for balancer pool exits is malformed and will result in all withdrawal attempts failing, trapping the user permanently. 

## Vulnerability Detail

[AuraSpell.sol#L184-L189](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/AuraSpell.sol#L184-L189)

    wAuraPools.getVault(lpToken).exitPool(
        IBalancerPool(lpToken).getPoolId(),
        address(this),
        address(this),
        IBalancerVault.ExitPoolRequest(tokens, minAmountsOut, "", false)
    );

We see above that UserData is encoded as "". This is problematic as it doesn't contain the proper data for exiting the pool, causing all exit request to fail and trap the user permanently.

https://etherscan.io/address/0x5c6ee304399dbdb9c8ef030ab642b10820db8f56#code#F9#L50

    function exactBptInForTokenOut(bytes memory self) internal pure returns (uint256 bptAmountIn, uint256 tokenIndex) {
        (, bptAmountIn, tokenIndex) = abi.decode(self, (WeightedPool.ExitKind, uint256, uint256));
    }

UserData is decoded into the data shown above when using ExitKind = 0. Since the exit uses "" as the user data this will be decoded as 0 a.k.a [EXACT_BPT_IN_FOR_ONE_TOKEN_OUT](https://etherscan.io/address/0x5c6ee304399dbdb9c8ef030ab642b10820db8f56#code#F24#L50). This is problematic because the token index and bptAmountIn should also be encoded in user data for this kind of exit. Since it isn't the exit call will always revert and the user will be permanently trapped.

## Impact

Users will be permanently trapped, unable to withdraw

## Code Snippet

https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/AuraSpell.sol#L149-L224

## Tool used

Manual Review

## Recommendation

Encode the necessary exit data in userData

# Issue H-9: WAuraPools will irreversibly break if reward tokens are added to pool after deposit 

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/127 

## Found by 
0x52, Ch\_301

## Summary

WAuraPools will irreversibly break if reward tokens are added to pool after deposit due to an OOB error on accExtPerShare.

## Vulnerability Detail

[WAuraPools.sol#L166-L189](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/wrapper/WAuraPools.sol#L166-L189)

        uint extraRewardsCount = IAuraRewarder(crvRewarder)
            .extraRewardsLength(); <- @audit-issue rewardTokenCount pulled fresh
        tokens = new address[](extraRewardsCount + 1);
        rewards = new uint256[](extraRewardsCount + 1);

        tokens[0] = IAuraRewarder(crvRewarder).rewardToken();
        rewards[0] = _getPendingReward(
            stCrvPerShare,
            crvRewarder,
            amount,
            lpDecimals
        );

        for (uint i = 0; i < extraRewardsCount; i++) {
            address rewarder = IAuraRewarder(crvRewarder).extraRewards(i);

            @audit-issue attempts to pull from array which will be too small if tokens are added
            uint256 stRewardPerShare = accExtPerShare[tokenId][i];
            tokens[i + 1] = IAuraRewarder(rewarder).rewardToken();
            rewards[i + 1] = _getPendingReward(
                stRewardPerShare,
                rewarder,
                amount,
                lpDecimals
            );
        }

accExtPerShare stores the current rewardPerToken when the position is first created. It stores it as an array and only stores values for reward tokens that have been added prior to minting. This creates an issue if a reward token is added because now it will attempt to pull a value for an index that doesn't exist and throw an OOB error.

This is problematic because pendingRewards is called every single transaction via the isLiquidatable subcall in BlueBerryBank#execute.

## Impact

WAuraPools will irreversibly break if reward tokens are added to pool after

## Code Snippet

[WAuraPools.sol#L152-L190](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/wrapper/WAuraPools.sol#L152-L190)

## Tool used

Manual Review

## Recommendation

Use a mapping rather than an array to store values

# Issue H-10: ShortLongSpell#_withdraw checks slippage limit but never applies it making it useless 

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/126 

## Found by 
0x52, Ch\_301

## Summary

Slippage limits protect the protocol in the event that a malicious user wants to extract value via swaps, this is an important protection in the event that a user finds a way to trick collateral requirements. Currently the sell slippage is checked but never applied so it is useless.

## Vulnerability Detail

See summary.

## Impact

Slippage limit protections are ineffective for ShortLongSpell

## Code Snippet

[ShortLongSpell.sol#L160-L20](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/ShortLongSpell.sol#L160-L202)

## Tool used

Manual Review

## Recommendation

Apply sell slippage after it is checked

# Issue H-11: ConvexSpell#closePositionFarm removes liquidity without any slippage protection 

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/124 

## Found by 
0x52, Breeje, Ch\_301, n1punp

## Summary

ConvexSpell#closePositionFarm removes liquidity without any slippage protection allowing withdraws to be sandwiched and stolen. Curve liquidity has historically been strong but for smaller pairs their liquidity is getting low enough that it can be manipulated via flashloans. 

## Vulnerability Detail

[ConvexSpell.sol#L204-L208](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/ConvexSpell.sol#L204-L208)

            ICurvePool(pool).remove_liquidity_one_coin(
                amountPosRemove,
                int128(tokenIndex),
                0
            );

Liquidity is removed as a single token which makes it vulnerable to sandwich attacks but no slippage protection is implemented. The same issue applies to CurveSpell.

## Impact

User withdrawals can be sandwiched

## Code Snippet

[ConvexSpell.sol#L147-L230](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/ConvexSpell.sol#L147-L230)

[CurveSpell.sol#L143-L223](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/CurveSpell.sol#L143-L223)

## Tool used

Manual Review

## Recommendation

Allow user to specify min out

# Issue H-12: Potential flash loan attack vulnerability in `getPrice` function of CurveOracle 

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/123 

## Found by 
Bauer, helpMePlease

## Summary
During a security review of the `getPrice` function in the CurveOracle, a potential flash loan attack vulnerability was identified.

## Vulnerability Detail
The `getPrice` function retrieves the spot price of each token in a Curve LP pool, calculates the minimum price among them, and multiplies it by the virtual price of the LP token to determine the USD value of the LP token. If the price of one or more tokens in the pool is manipulated, this can cause the minimum price calculation to be skewed, leading to an incorrect USD value for the LP token. This can be exploited by attackers to make a profit at the expense of other users.

## Impact
This vulnerability could potentially allow attackers to manipulate the price of tokens in Curve LP pools and profit at the expense of other users. If exploited, this vulnerability could result in significant financial losses for affected users.

## Code Snippet
https://github.com/sherlock-audit/2023-04-blueberry/blob/96eb1829571dc46e1a387985bd56989702c5e1dc/blueberry-core/contracts/oracle/CurveOracle.sol#L122

## Tool used

Manual Review

## Recommendation
use TWAP to determine the prices of the underlying assets in the pool. 

# Issue H-13: Users are forced to swap all reward tokens with no slippage protection 

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/121 

## Found by 
0x52, Bauer, Breeje, J4de, ctf\_sec, n1punp, nobody2018

## Summary

AuraSpell forces users to swap their reward tokens to debt token but doesn't allow them to specify any slippage values.

## Vulnerability Detail

[AuraSpell.sol#L193-L203
](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/AuraSpell.sol#L193-L203)

        for (uint256 i = 0; i < rewardTokens.length; i++) {
            uint256 rewards = _doCutRewardsFee(rewardTokens[i]);
            _ensureApprove(rewardTokens[i], address(swapRouter), rewards);
            swapRouter.swapExactTokensForTokens(
                rewards,
                0,
                swapPath[i],
                address(this),
                type(uint256).max
            );
        }

Above all reward tokens are swapped and always use 0 for min out meaning that deposits will be sandwiched and stolen.

## Impact

All reward tokens can be sandwiched and stolen

## Code Snippet

[AuraSpell.sol#L149-L224](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/AuraSpell.sol#L149-L224)

## Tool used

Manual Review

## Recommendation

Allow user to specify slippage parameters for all reward tokens

# Issue H-14: AuraSpell#openPositionFarm uses incorrect join type for balancer 

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/120 

## Found by 
0x52, cuthalion0x

## Summary

The JoinPoolRequest uses "" for userData meaning that it will decode into 0. This is problematic because join requests of type 0 are "init" type joins and will revert for pools that are already initialized. 

## Vulnerability Detail

https://etherscan.io/address/0x5c6ee304399dbdb9c8ef030ab642b10820db8f56#code#F24#L49

    enum JoinKind { INIT, EXACT_TOKENS_IN_FOR_BPT_OUT, TOKEN_IN_FOR_EXACT_BPT_OUT }

We see above that enum JoinKind is INIT for 0 values.

https://etherscan.io/address/0x5c6ee304399dbdb9c8ef030ab642b10820db8f56#code#F24#L290

            return _joinExactTokensInForBPTOut(balances, normalizedWeights, userData);
        } else if (kind == JoinKind.TOKEN_IN_FOR_EXACT_BPT_OUT) {
            return _joinTokenInForExactBPTOut(balances, normalizedWeights, userData);
        } else {
            _revert(Errors.UNHANDLED_JOIN_KIND);
        }

Here user data is decoded into join type and since it is "" it will decode to type 0 which will result in a revert.

## Impact

Users will be unable to open any farm position on AuraSpell

## Code Snippet

[AuraSpell.sol#L63-L147](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/AuraSpell.sol#L63-L147)

## Tool used

Manual Review

## Recommendation

Uses JoinKind = 1 for user data

# Issue M-1: Missing checks for whether Arbitrum Sequencer is active 

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/142 

## Found by 
0xepley, Bauchibred, Bauer, Brenzee, J4de, ctf\_sec, deadrxsezzz, tallo

## Summary

Missing checks for whether Arbitrum Sequencer is active

## Vulnerability Detail

the onchain deployment context is changed, in prev contest the protocol only attemps to deploy the code to ethereum while in the current contest

the protocol intends to deploy to arbtrium as well!

Chainlink recommends that users using price oracles, check whether the Arbitrum sequencer is active

https://docs.chain.link/data-feeds#l2-sequencer-uptime-feeds

If the sequencer goes down, the index oracles may have stale prices, since L2-submitted transactions (i.e. by the aggregating oracles) will not be processed.

## Impact

Stale prices, e.g. if USDC were to de-peg while the sequencer is offline, stale price is used and can result in false liquidation or over-borrowing.

## Code Snippet

https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/oracle/ChainlinkAdapterOracle.sol#L76-L98

## Tool used

Manual Review

## Recommendation

Use sequencer oracle to determine whether the sequencer is offline or not, and don't allow orders to be executed while the sequencer is offline.

# Issue M-2: rewardTokens removed from WAuraPool/WConvexPools will be lost forever 

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/128 

## Found by 
0x52

## Summary

pendingRewards pulls a fresh count of reward tokens each time it is called. This is problematic if reward tokens are ever removed from the the underlying Aura/Convex pools because it means that they will no longer be distributed and will be locked in the contract forever.

## Vulnerability Detail

[WAuraPools.sol#L166-L189](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/wrapper/WAuraPools.sol#L166-L189)

        uint extraRewardsCount = IAuraRewarder(crvRewarder)
            .extraRewardsLength();
        tokens = new address[](extraRewardsCount + 1);
        rewards = new uint256[](extraRewardsCount + 1);

        tokens[0] = IAuraRewarder(crvRewarder).rewardToken();
        rewards[0] = _getPendingReward(
            stCrvPerShare,
            crvRewarder,
            amount,
            lpDecimals
        );

        for (uint i = 0; i < extraRewardsCount; i++) {
            address rewarder = IAuraRewarder(crvRewarder).extraRewards(i);
            uint256 stRewardPerShare = accExtPerShare[tokenId][i];
            tokens[i + 1] = IAuraRewarder(rewarder).rewardToken();
            rewards[i + 1] = _getPendingReward(
                stRewardPerShare,
                rewarder,
                amount,
                lpDecimals
            );
        }

In the lines above we can see that only tokens that are currently available on the pool. This means that if tokens are removed then they are no longer claimable and will be lost to those entitled to shares.

## Impact

Users will lose reward tokens if they are removed

## Code Snippet

[WAuraPools.sol#L152-L190](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/wrapper/WAuraPools.sol#L152-L190)

## Tool used

Manual Review

## Recommendation

Reward tokens should be stored with the tokenID so that it can still be paid out even if it the extra rewardToken is removed.

# Issue M-3: Issue 327 from previous contest has not been fixed 

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/125 

## Found by 
0x52

## Summary

[Issue 327](https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/327) has not been fixed. The issue is labeled as "Won't Fix" but dev comments indicates that they are still meant to be fixed. Comments from discord:

[Watson Question: ](https://discord.com/channels/812037309376495636/1100436073055780894/1101829382768697415)

`@Gornutz | Blueberry I assume findings that address issues that were marked as "won't fix" in the previous contest are not valid, is that correct?`

[Dev Response: ](https://discord.com/channels/812037309376495636/1100436073055780894/1101911014892638390)

`they were fixed but not by the solution provided`

## Vulnerability Detail

[BasicSpell.sol#L198-L207](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/BasicSpell.sol#L198-L207)

    function _validateMaxPosSize(uint256 strategyId) internal view {
        Strategy memory strategy = strategies[strategyId];
        IERC20Upgradeable lpToken = IERC20Upgradeable(strategy.vault);
        uint256 lpBalance = lpToken.balanceOf(address(this));
        uint256 lpPrice = bank.oracle().getPrice(address(lpToken));
        uint256 curPosSize = (lpPrice * lpBalance) /
            10 ** IERC20MetadataUpgradeable(address(lpToken)).decimals();
        if (curPosSize > strategy.maxPositionSize)
            revert Errors.EXCEED_MAX_POS_SIZE(strategyId);
    }

We see above that _validateMaxPosSize still uses the lpToken.balnceOf which as pointed out by [Issue 327](https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/327) from the previous contest does not actually prevent users from exceeding the max position size.

## Impact

Users can still bypass position size limit

## Code Snippet

[BasicSpell.sol#L198-L207](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/BasicSpell.sol#L198-L207)

## Tool used

Manual Review

## Recommendation

See [Issue 327](https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/327) 

# Issue M-4: AuraSpell#closePositionFarm requires users to swap all reward tokens through same router 

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/122 

## Found by 
0x52

## Summary

AuraSpell#closePositionFarm requires users to swap all reward tokens through same router. This is problematic as it is very unlikely that a UniswapV2 router will have good liquidity sources for all tokens and will result in users experiencing forced losses to their reward token.  

## Vulnerability Detail

[AuraSpell.sol#L193-L203
](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/AuraSpell.sol#L193-L203)

        for (uint256 i = 0; i < rewardTokens.length; i++) {
            uint256 rewards = _doCutRewardsFee(rewardTokens[i]);
            _ensureApprove(rewardTokens[i], address(swapRouter), rewards);
            swapRouter.swapExactTokensForTokens(
                rewards,
                0,
                swapPath[i],
                address(this),
                type(uint256).max
            );
        }

All tokens are forcibly swapped through a single router.

## Impact

Users will be forced to swap through a router even if it doesn't have good liquidity for all tokens

## Code Snippet

[AuraSpell.sol#L149-L224](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/AuraSpell.sol#L149-L224)

## Tool used

Manual Review

## Recommendation

Allow users to use an aggregator like paraswap or multiple routers instead of only one single UniswapV2 router.

# Issue M-5: Issue 94 from previous contest has not been fixed 

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/118 

## Found by 
0x52, Bauchibred, cducrest-brainbot, deadrxsezzz, helpMePlease, kaysoft, peanuts, tsvetanovv

## Summary

[Issue 94](https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/94) still exists exactly even though it was marked as "will fix".

## Vulnerability Detail

See [Issue 94](https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/94)

## Impact

See [Issue 94](https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/94)

## Code Snippet

[ChainlinkAdapterOracle.sol#L77-L97](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/oracle/ChainlinkAdapterOracle.sol#L77-L97)

## Tool used

Manual Review

## Recommendation

See [Issue 94](https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/94)

# Issue M-6: Issue 290 from previous contest has not been fully addressed by fixes 

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/117 

## Found by 
0x52, HonorLt, cducrest-brainbot, dacian

## Summary

[Issue 290](https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/290) from the previous contest points out that users may be liquidated without the chance to repay their debt. Liquidate was changed to only be allowed when repayment was allowed. While this does address some of the problem this will still fail to protect users who become liquidatable during the period of time that repay has been disabled.

MEV bots are typically used to liquidate positions since it is always more profitable to liquidate the vault even if a user tries to pay off their debt on the same black that repay is enabled, they will still be liquidated because of frontrunning.

## Vulnerability Detail

See summary.

## Impact

Users who become liquidatable during a repay pause will still be unable to save their position

## Code Snippet

[BlueBerryBank.sol#L487-L548](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/BlueBerryBank.sol#L487-L548)

## Tool used

Manual Review

## Recommendation

When repay is paused and then resumed, put a timer that prevents liquidations for some amount of time after (i.e. 4 hours) so that users can fairly repay their position after repayment has been resumed.

# Issue M-7: BlueBerryBank#getPositionValue causes DOS if reward token is added that doens't have an oracle 

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/115 

## Found by 
0x52, nobody2018

## Summary

collToken.pendingRewards pulls the most recent reward list from Aura/Convex. In the event that reward tokens are added to pools that don't currently have an oracle then it will DOS every action (repaying, liquidating, etc.). While this is only temporary it prevents liquidation which is a key process that should have 100% uptime otherwise the protocol could easily be left with bad debt.

## Vulnerability Detail

[BlueBerryBank.sol#L408-L413](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/BlueBerryBank.sol#L408-L413)

          (address[] memory tokens, uint256[] memory rewards) = IERC20Wrapper(
              pos.collToken
          ).pendingRewards(pos.collId, pos.collateralSize);
          for (uint256 i; i < tokens.length; i++) {
              rewardsValue += oracle.getTokenValue(tokens[i], rewards[i]);
          }

Using the pendingRewards method pulls a fresh list of all tokens. When a token is added as a reward but can't be priced then the call to getTokenValue will revert. Since getPostionValue is used in liquidations, it temporarily breaks liquidations which in a volatile market can cause bad debt to accumulate.

## Impact

Temporary DOS to liquidations which can result in bad debt

## Code Snippet

[BlueBerryBank.sol#L392-L417](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/BlueBerryBank.sol#L392-L417)

## Tool used

Manual Review

## Recommendation

Return zero valuation if extra reward token can't be priced.

# Issue M-8: Users can fail to closePositionFarm and lose their funds 

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/64 

## Found by 
Bauer

## Summary
If self.is_killed in the curve pool contract  becomes true, user may be unable to call the `CurveSpell.closePositionFarm()` function to  repay his debt, resulting in his assets being liquidated.


## Vulnerability Detail
The `CurveSpell.closePositionFarm()` function is used to unwind a position on a strategy that involves farming CRV rewards through staking LP tokens in a Curve pool. Inside the function, the protocol swaps the harvested CRV tokens to the debt token, and calculates the actual amount of LP tokens to remove from the Curve pool. It then removes the LP tokens using the remove_liquidity_one_coin function of the Curve pool. 
```solidity
   int128 tokenIndex;
            for (uint256 i = 0; i < tokens.length; i++) {
                if (tokens[i] == pos.debtToken) {
                    tokenIndex = int128(uint128(i));
                    break;
                }
            }

            ICurvePool(pool).remove_liquidity_one_coin(
                amountPosRemove,
                int128(tokenIndex),
                0
            );
        }

        // 5. Withdraw isolated collateral from Bank
        _doWithdraw(param.collToken, param.amountShareWithdraw);

        // 6. Repay
        {
            // Compute repay amount if MAX_INT is supplied (max debt)
            uint256 amountRepay = param.amountRepay;
            if (amountRepay == type(uint256).max) {
                amountRepay = bank.currentPositionDebt(bank.POSITION_ID());
            }
            _doRepay(param.borrowToken, amountRepay);
        }

        _validateMaxLTV(param.strategyId);
```
If self.is_killed in the curve pool contract  becomes true, calling such `remove_liquidity_one_coin()` function would always revert. In this case, calling the `CurveSpell.closePositionFarm()` function reverts. When user's position is about to be liquidated, if the `closePositionFarm()` function is DOS'ed,user may be unable to repay his debt, resulting in the user losing their funds
```solidity
def remove_liquidity_one_coin(
    _token_amount: uint256,
    i: int128,
    _min_amount: uint256
) -> uint256:
    """
    @notice Withdraw a single coin from the pool
    @param _token_amount Amount of LP tokens to burn in the withdrawal
    @param i Index value of the coin to withdraw
    @param _min_amount Minimum amount of coin to receive
    @return Amount of coin received
    """
    assert not self.is_killed  # dev: is killed

    dy: uint256 = 0
    dy_fee: uint256 = 0
    dy, dy_fee = self._calc_withdraw_one_coin(_token_amount, i)

```

## Impact
If self.is_killed in the curve pool contract  becomes true, user may be unable to repay his debt, resulting in his assets being liquidated.

## Code Snippet
https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/CurveSpell.sol#L197

## Tool used

Manual Review

## Recommendation

# Issue M-9: The protocol  will not be able to add liquidity on the curve with another token with a balance. 

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/47 

## Found by 
Bauer, nobody2018

## Summary
The `CurveSpell` protocol only ensure approve curve pool to spend its borrow token. Hence, it will not be able to add liquidity on the curve with another token with a balance.

## Vulnerability Detail
The  `openPositionFarm()` function enables user to open a leveraged position in a yield farming strategy by borrowing funds and using them to add liquidity to a Curve pool, while also taking into account certain risk management parameters such as maximum LTV and position size. When add liquidity on curve ,the protocol use the borrowed token and the collateral token, it checks the number of tokens in the pool and creates an array of the supplied token amounts to be passed to the add_liquidity function. Then the curve will transfer the tokens from the protocol and mint lp tokens to the protocol. However, the protocol only ensure approve curve pool to spend its borrow token. Hence, it will not be able to add liquidity on the curve with another token with a balance.
```solidity
 // 3. Add liquidity on curve
        _ensureApprove(param.borrowToken, pool, borrowBalance);
        if (tokens.length == 2) {
            uint256[2] memory suppliedAmts;
            for (uint256 i = 0; i < 2; i++) {
                suppliedAmts[i] = IERC20Upgradeable(tokens[i]).balanceOf(
                    address(this)
                );
            }
            ICurvePool(pool).add_liquidity(suppliedAmts, minLPMint);
        } else if (tokens.length == 3) {
            uint256[3] memory suppliedAmts;
            for (uint256 i = 0; i < 3; i++) {
                suppliedAmts[i] = IERC20Upgradeable(tokens[i]).balanceOf(
                    address(this)
                );
            }
            ICurvePool(pool).add_liquidity(suppliedAmts, minLPMint);
        } else if (tokens.length == 4) {
            uint256[4] memory suppliedAmts;
            for (uint256 i = 0; i < 4; i++) {
                suppliedAmts[i] = IERC20Upgradeable(tokens[i]).balanceOf(
                    address(this)
                );
            }
            ICurvePool(pool).add_liquidity(suppliedAmts, minLPMint);
        }

```

## Impact
The protocol  will not be able to add liquidity on the curve with another token with a balance.
## Code Snippet
https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/CurveSpell.sol#L90-L115
## Tool used

Manual Review

## Recommendation
Allow the curve pool to spend tokens that have a balance in the protocol to add liquidity

# Issue M-10: AuraSpell openPositionFarm does not join pool 

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/46 

## Found by 
Ch\_301, cducrest-brainbot, cuthalion0x, nobody2018

## Summary

The function to open a position for the AuraSpell does not join the pool due to wrong conditional check.

## Vulnerability Detail

The function deposits collateral into the bank, borrow tokens, and attempts to join the pool:

```solidity
    function openPositionFarm(
        OpenPosParam calldata param
    )
        external
        existingStrategy(param.strategyId)
        existingCollateral(param.strategyId, param.collToken)
    {
        ...
        // 1. Deposit isolated collaterals on Blueberry Money Market
        _doLend(param.collToken, param.collAmount);

        // 2. Borrow specific amounts
        uint256 borrowBalance = _doBorrow(
            param.borrowToken,
            param.borrowAmount
        );

        // 3. Add liquidity on Balancer, get BPT
        {
            IBalancerVault vault = wAuraPools.getVault(lpToken);
            _ensureApprove(param.borrowToken, address(vault), borrowBalance);

            (address[] memory tokens, uint256[] memory balances, ) = wAuraPools
                .getPoolTokens(lpToken);
            uint[] memory maxAmountsIn = new uint[](2);
            maxAmountsIn[0] = IERC20(tokens[0]).balanceOf(address(this));
            maxAmountsIn[1] = IERC20(tokens[1]).balanceOf(address(this));

            uint totalLPSupply = IBalancerPool(lpToken).totalSupply();
            // compute in reverse order of how Balancer's `joinPool` computes tokenAmountIn
            uint poolAmountFromA = (maxAmountsIn[0] * totalLPSupply) /
                balances[0];
            uint poolAmountFromB = (maxAmountsIn[1] * totalLPSupply) /
                balances[1];
            uint poolAmountOut = poolAmountFromA > poolAmountFromB
                ? poolAmountFromB
                : poolAmountFromA;

            bytes32 poolId = bytes32(param.farmingPoolId);
            if (poolAmountOut > 0) {
                vault.joinPool(
                    poolId,
                    address(this),
                    address(this),
                    IBalancerVault.JoinPoolRequest(
                        tokens,
                        maxAmountsIn,
                        "",
                        false
                    )
                );
            }
        }
        ...
    }
```

The function only borrowed one type of tokens from the bank so the contract only owns one type of token. As a result one of the `maxAmountsIn` value is 0. Either `poolAmountFromA` or `poolAmountFromB` is 0 as a result of computation. `poolAmountOut` is the minimal value of `poolAmountFromA` and `poolAmountFromB`, it is 0. The following check `if (poolAmountOut > 0)` will always fail and the pool will never be joined.

## Impact

The rest of the function proceeds correctly without reverting. Users will think they joined the pool and are earning reward while they are not earning anything. This is a loss of funds to the user.

## Code Snippet

https://github.com/sherlock-audit/2023-04-blueberry/blob/96eb1829571dc46e1a387985bd56989702c5e1dc/blueberry-core/contracts/spell/AuraSpell.sol#L63-L147

## Tool used

Manual Review

## Recommendation

It is hard to tell the intent of the developer from this check. Maybe the issue is simply that `poolAmountOut` should be the sum or the max value out of `poolAmountFromA` and `poolAmountFromB` instead of the min.


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

# Issue M-2: IchiSpell applies slippage to sqrtPrice which is wrong and leads to unpredictable slippage 

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/131 

## Found by 
0x52

## Summary

UniswapV3 uses the sqrt of the price rather than the price itself, but slippage is applied directly to the sqrt of the price which leads to unpredictable prices.

## Vulnerability Detail

[IchiSpell.sol#L211-L222](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/IchiSpell.sol#L211-L222)

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

We see above that the sell slippage is applied to the sqrtPrice instead of the actual price. This means that applied slippage limits are not applied correctly and can be much larger than intended.

Example:
The protocol wants to limit slippage to 10%. This limit is applied to the sqrt price so if the sqrt price is 10 (price = 100) then it will apply 10% to that making it 9. Now to get the true price we need to square the price which gives us a price of 81. This translates to a true slippage limit of 19% rather than 10%.

## Impact

Slippage limits are much larger than intended

## Code Snippet

[IchiSpell.sol#L181-L236](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/IchiSpell.sol#L181-L236)

## Tool used

Manual Review

## Recommendation

Apply slippage requirement on price not sqrt price

# Issue M-3: rewardTokens removed from WAuraPool/WConvexPools will be lost forever 

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

# Issue M-4: Issue 327 from previous contest has not been fixed 

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

# Issue M-5: AuraSpell#closePositionFarm requires users to swap all reward tokens through same router 

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

# Issue M-6: Issue 94 from previous contest has not been fixed 

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

# Issue M-7: Issue 290 from previous contest has not been fully addressed by fixes 

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/117 

## Found by 
0x52, HonorLt, cducrest-brainbot

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

# Issue M-8: BlueBerryBank#getPositionValue causes DOS if reward token is added that doens't have an oracle 

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

# Issue M-9: `getPositionRisk()` will return a wrong value of risk 

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/97 

## Found by 
Ch\_301

## Summary
In order to interact with SPELL the users need to `lend()` some collateral which is known as **Isolated Collateral** and the SoftVault will deposit them into Compound protocol to generate some lending interest (to earn passive yield)  

## Vulnerability Detail
to [liquidate](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/BlueBerryBank.sol#L487-L548) a position this function `isLiquidatable()` should return `true`
```solidity
    function isLiquidatable(uint256 positionId) public view returns (bool) {
        return
            getPositionRisk(positionId) >=
            banks[positions[positionId].underlyingToken].liqThreshold;
    }
```
and it is subcall to `getPositionRisk()`
```solidity
    function getPositionRisk(
        uint256 positionId
    ) public view returns (uint256 risk) {
        uint256 pv = getPositionValue(positionId);          
        uint256 ov = getDebtValue(positionId);             
        uint256 cv = getIsolatedCollateralValue(positionId);

        if (
            (cv == 0 && pv == 0 && ov == 0) || pv >= ov // Closed position or Overcollateralized position
        ) {
            risk = 0;
        } else if (cv == 0) {
            // Sth bad happened to isolated underlying token
            risk = Constants.DENOMINATOR;
        } else {
            risk = ((ov - pv) * Constants.DENOMINATOR) / cv;
        }
    }
```
as we can see the `cv`  is a critical value in terms of the calculation of `risk `
the `cv` is returned by `getIsolatedCollateralValue()`

```solidity
    function getIsolatedCollateralValue(
        uint256 positionId
    ) public view override returns (uint256 icollValue) {
        Position memory pos = positions[positionId];
        // NOTE: exchangeRateStored has 18 decimals.
        uint256 underlyingAmount;
        if (_isSoftVault(pos.underlyingToken)) {
            underlyingAmount =                                              
                (ICErc20(banks[pos.debtToken].bToken).exchangeRateStored() * 
                    pos.underlyingVaultShare) /
                Constants.PRICE_PRECISION; 
        } else {
            underlyingAmount = pos.underlyingVaultShare;
        }
        icollValue = oracle.getTokenValue(
            pos.underlyingToken,
            underlyingAmount
        );
    }
 ```
and it uses `exchangeRateStored()` to ask Compound (CToken.sol) for the exchange rate 
[from `CToken` contract ](https://github.com/compound-finance/compound-protocol/blob/master/contracts/CToken.sol#LL281C18-L281C18)
```diff
This function does not accrue interest before calculating the exchange rate
``` 
so the `getPositionRisk()` will return a wrong value of risk because the interest does not accrue for this position 

## Impact
the user (position) could get liquidated even if his position is still healthy 
  
## Code Snippet
https://github.com/compound-finance/compound-protocol/blob/master/contracts/CToken.sol#LL270C1-L286C6
```solidity
    /**
     * @notice Accrue interest then return the up-to-date exchange rate
     * @return Calculated exchange rate scaled by 1e18
     */
    function exchangeRateCurrent() override public nonReentrant returns (uint) {
        accrueInterest();
        return exchangeRateStored();
    }

    /**
     * @notice Calculates the exchange rate from the underlying to the CToken
     * @dev This function does not accrue interest before calculating the exchange rate
     * @return Calculated exchange rate scaled by 1e18
     */
    function exchangeRateStored() override public view returns (uint) {
        return exchangeRateStoredInternal();
    }
```    
## Tool used

Manual Review

## Recommendation
You shoud use `exchangeRateCurrent()` to  Accrue interest first.

# Issue M-10: Potential DOS / lack of acccess to oracle price due to unhandled chainlink revert 

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/77 

## Found by 
Bauchibred, darksnow


## Summary

Chainlink's latestRoundData() is being implemented in scope, and the call to this could potentially revert and make it impossible to query any prices. This could lead to permanent denial of service.

## Vulnerability Detail

[See this](https://blog.openzeppelin.com/secure-smart-contract-guidelines-the-dangers-of-price-oracles/)
The ChainlinkAdapterOracle.getPrice() function makes use of Chainlink's latestRoundData() to get the latest price. However, there is no fallback logic to be executed when the access to the Chainlink data feed is denied by Chainlink's multisigs. While currently there’s no whitelisting mechanism to allow or disallow contracts from reading prices, powerful multisigs can tighten these access controls. In other words, the multisigs can immediately block access to price feeds at will.

## Impact

Denial of service to the protocol due to ChainlinkAdapterOracle.getPrice() reverting

## Code Snippet

https://github.com/sherlock-audit/2023-04-blueberry/blob/96eb1829571dc46e1a387985bd56989702c5e1dc/blueberry-core/contracts/oracle/ChainlinkAdapterOracle.sol#L77-L97

## Tool used

Manual Review

## Recommendation

The logic for getting the token's price from the Chainlink data feed should be placed in the try block, while some fallback logic when the access to the chainlink oracle data feed is denied should be placed in the catch block.

In short use a try/catch block.


# Issue M-11: Users can fail to closePositionFarm and lose their funds 

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

# Issue M-12: Dos attack to openPositionFarm() 

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/48 

## Found by 
Bauer

## Summary
 A bad actor can transfer 1 wei worth of the corresponding  token to the protocol before user calling the `openPositionFarm()` function, in order to increase the protocol's balance and build an LP position to call ICurvePool(pool).add_liquidity(), since the protocol only allows the curvel pool to spend the borrowed token, this will cause an error when Curve attempts to transfer other tokens out of the protocol.


## Vulnerability Detail
The `openPositionFarm()` function is used to add liquidity to Curve pool with 2 underlying tokens, with staking to Curve gauge. When add liquidity on curve ,the protocol use the borrowed token and the collateral token, it checks the number of tokens in the pool and creates an array of the supplied token amounts to be passed to the add_liquidity function.If the pool contains three tokens, the process is repeated with an array of three elements, and if the pool contains four tokens, an array of four elements is created and used. Here is the problem,a bad actor may transfer 1 wei worth of the corresponding  token to the protocol before user calling the `openPositionFarm()` function, in order to increase the protocol's balance and build an LP position to call ICurvePool(pool).add_liquidity(). However, since the protocol only allows the curvel pool to spend the borrowed token, this will cause an error when Curve attempts to transfer other tokens out of the protocol.
```solidity
  uint256 borrowBalance = _doBorrow(
            param.borrowToken,
            param.borrowAmount
        );

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
User will not able to call the `openPositionFarm()` function to add liquidity to Curve pool
## Code Snippet
https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/spell/CurveSpell.sol#L84-L115
## Tool used

Manual Review

## Recommendation

# Issue M-13: The protocol  will not be able to add liquidity on the curve with another token with a balance. 

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

# Issue M-14: AuraSpell openPositionFarm does not join pool 

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

# Issue M-15: auraPools.deposit and auraPools.withdraw  boolean return value not handled in WAuraPools.sol 

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/41 

## Found by 
Bauer

## Summary
auraPools.deposit() and auraPools.withdraw() boolean return value not handled in WAuraPools.sol


## Vulnerability Detail
The `WAuraPools.mint()` function allows users to deposit "amount" of a specific pool token, identified by "pid". The deposited tokens are then transferred from the user's address to the contract's address. The function also ensures that the contract is approved to spend the deposited tokens by calling the "_ensureApprove" function with the specified amount.
The `deposit()` function of the `auraPools` contract is then called to deposit the tokens into the specified pool.
However, the protocol does not handle the AuraPool.withdrawAndUnwrap() boolean return value.
```solidity
 function mint(
        uint256 pid,
        uint256 amount
    ) external nonReentrant returns (uint256 id) {
        (address lpToken, , , address crvRewarder, , ) = getPoolInfoFromPoolId(
            pid
        );
        IERC20Upgradeable(lpToken).safeTransferFrom(
            msg.sender,
            address(this),
            amount
        );

        _ensureApprove(lpToken, address(auraPools), amount);
        auraPools.deposit(pid, amount, true);

        uint256 crvRewardPerToken = IAuraRewarder(crvRewarder).rewardPerToken();
        id = encodeId(pid, crvRewardPerToken);
        _mint(msg.sender, id, amount, "");
        // Store extra rewards info
        uint extraRewardsCount = IAuraRewarder(crvRewarder)
            .extraRewardsLength();
        for (uint i = 0; i < extraRewardsCount; i++) {
            address extraRewarder = IAuraRewarder(crvRewarder).extraRewards(i);
            uint rewardPerToken = IAuraRewarder(extraRewarder).rewardPerToken();
            accExtPerShare[id].push(rewardPerToken);
        }
    }
```
In the AuraBooster implmenetation, a Boolean is indeed returned to acknowledge that deposit is completely successfully.

https://etherscan.io/address/0x7818A1DA7BD1E64c199029E86Ba244a9798eEE10#code#F34#L1
```solidity
  /**
     * @notice  Deposits an "_amount" to a given gauge (specified by _pid), mints a `DepositToken`
     *          and subsequently stakes that on Convex BaseRewardPool
     */
    function deposit(uint256 _pid, uint256 _amount, bool _stake) public returns(bool){

```
The same issue for `auraPools.withdraw()`
## Impact
If the boolean value is not handled, the transaction may fail silently.


## Code Snippet
https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/wrapper/WAuraPools.sol#L209
https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/wrapper/WAuraPools.sol#L248

## Tool used

Manual Review

## Recommendation
Recommend checking for success return value

```solidity
  bool depositSuccess =   auraPools.deposit(pid, amount, true);
 require(depositSuccess , 'deposit failed');

```

# Issue M-16: IchiVaultOracle getPrice will fail during price crashes 

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/28 

## Found by 
cducrest-brainbot

## Summary

The function to get the price of the IchiVault LP token will fail when TWAP and spot price differ too much. This will be the case when price of the LP token crashes. 

The oracle will revert and positions using IchiVault LP token won't be able to be repaid / liquidated when price crashes, when this is needed the most.

## Vulnerability Detail

The function `getPrice()` checks the spot and twap price of the LP token, it reverts when they differ too much:

```solidity
    function getPrice(address token) external view override returns (uint256) {
        IICHIVault vault = IICHIVault(token);
        uint256 totalSupply = vault.totalSupply();
        if (totalSupply == 0) return 0;

        address token0 = vault.token0();
        address token1 = vault.token1();

        // Check price manipulations on Uni V3 pool by flashloan attack
        uint256 spotPrice = spotPrice0InToken1(vault);
        uint256 twapPrice = twapPrice0InToken1(vault);
        uint256 maxPriceDeviation = maxPriceDeviations[token0];
        if (!_isValidPrices(spotPrice, twapPrice, maxPriceDeviation))
            revert Errors.EXCEED_DEVIATION();

        // Total reserve / total supply
        (uint256 r0, uint256 r1) = vault.getTotalAmounts();
        uint256 px0 = base.getPrice(address(token0));
        uint256 px1 = base.getPrice(address(token1));
        uint256 t0Decimal = IERC20Metadata(token0).decimals();
        uint256 t1Decimal = IERC20Metadata(token1).decimals();

        uint256 totalReserve = (r0 * px0) /
            10 ** t0Decimal +
            (r1 * px1) /
            10 ** t1Decimal;

        return (totalReserve * 10 ** vault.decimals()) / totalSupply;
    }
```

## Impact

The twap period can range from 1 hour to 2 days. If the twap period is long enough or the `maxPriceDeviations` small enough, the pricing oracle will revert when price crashes (or spikes) and prevent actions on positions using IchiVault LP tokens.

The liquidation / repayment will be impossible when most needed, during important changes of market prices.

As noted in the comment and understood from the code, the intent of this check is to prevent price manipulation of the LP token. If the `maxPriceDeviations`, the price oracle is vulnerable to price manipulation since it does not the fair LP token pricing method.

## Code Snippet

https://github.com/sherlock-audit/2023-04-blueberry/blob/96eb1829571dc46e1a387985bd56989702c5e1dc/blueberry-core/contracts/oracle/IchiVaultOracle.sol#L110-L138

## Tool used

Manual Review

## Recommendation

Use the [fair lp token pricing](https://cmichel.io/pricing-lp-tokens/) strategy instead of checking twap and spot price.

# Issue M-17: Transaction will revert when using USDT tokens (or other non-compliant ERC20 tokens) 

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/15 

## Found by 
n1punp

## Summary
Transaction will revert when using USDT tokens

## Vulnerability Detail
USDT token has a non-standard `approve` function implementation, as it doesn't return a boolean. So, normal `IERC20` interface will cause the EVM to expect a boolean as a return value but it won't get any when `token` is USDT, and so the tx will revert. 


## Impact
Any contract functionality that utilizes `_ensureApprove` will cause tx revert when the token is USDT, including `lend`, `withdrawLend` , and executions in all spells.

## Code Snippet
https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/utils/EnsureApprove.sol#L22-L23

## Tool used

Manual Review

## Recommendation
- use `safeApprove` from OpenZeppelin's standard `SafeERC20.sol`

# Issue M-18: Accrue function is not called before executing some functions 

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/10 

## Found by 
Tendency, devScrooge

## Summary
As the NatSpec comments and documentation indicate, the functions `getDebtValue`, `getIsolatedCollateralValue`, `getPositionDebt`,  on the `BlueBerryBank` contract, the `accrue` function should be called first to get the current debt, but it is actually not being called. 

## Vulnerability Detail

The NatSpec lines [340](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/BlueBerryBank.sol#L340), [420](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/BlueBerryBank.sol#L420), [431](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/BlueBerryBank.sol#L431) and also in the [Blueberry docs](https://docs.blueberry.garden/developer-guides/contracts/blueberry-bank/blueberry-bank-contract) indicates that: `The function should be called after calling the accrue function to get the current debt`. 

But actually none of these function (`getDebtValue`, `getIsolatedCollateralValue`, `getPositionDebt`) are calling the `accrue` function before.

## Impact
No calling the `accrue` function before executing the mentioned function means that the following operations and/or calculations are not done with the actual value of the current debt, thus a non-correct value is being used. 

Inside the `BlueBerryBank` contract, all of the mentioned functions are called by functions that are called by other functions that implement the `poke `modifier, which in turn calls the accrue function. This means that the debt is going to be updated to the current one so the value will be correct but the `getDebtValue`, `getIsolatedCollateralValue`, `getPositionDebt` functions are public so future or external implemented contracts can call them and use a non update value for the current debt.

## Code Snippet
https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/BlueBerryBank.sol#L340,
https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/BlueBerryBank.sol#L420, 
https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/BlueBerryBank.sol#L431

## Tool used

Manual Review

## Recommendation
Add the `poke` modifier to the `getDebtValue`, `getIsolatedCollateralValue`, `getPositionDebt` functions so that if external contracts call to this functions a correct value of the current debt is going to be used correct.

# Issue M-19: Borrower can't repay but can be liquidated as token whitelist can prevent existing positions from repaying 

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/4 

## Found by 
dacian

## Summary
Borrower can't repay but can be liquidated as token whitelist can prevent existing positions from repaying.

## Vulnerability Detail
BlueBerryBank.repay() has onlyWhitelistedToken() modifier, while BlueBerryBank.liquidate() does not; both end up calling _repay(). If Borrower has an existing position and then the token is removed from the whitelist, Borrower is unable to repay but can still be liquidated.

## Impact
Borrower with existing position can't repay their loan but can be liquidated - this severely disadvantages the Borrower guaranteeing their liquidation with no possibility to repay.

## Code Snippet
BlueBerryBank.liquidate() [L487-491](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/BlueBerryBank.sol#L487-L491) vs BlueBerryBank.repay() [L718-721](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/BlueBerryBank.sol#L718-L721)

## Tool used
Weaponized Autism (I read through every single c4/sherlock lending/borrowing contest and examined every single high/medium finding, since the beginning. Kinda crazy right?)

## Recommendation
First please consider [Repayments Paused While Liquidations Enabled](https://dacian.me/lending-borrowing-defi-attacks#heading-repayments-paused-while-liquidations-enabled) from BlueBerry's first audit finding. BlueBerry addressed this issue by having liquidate() call isRepayAllowed() [L492](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/BlueBerryBank.sol#L492)

However the same state can also be reached due to the inconsistent use of onlyWhitelistedToken() modifier between repay() and liquidate(). So one potential fix is to have liquidate() also use onlyWhitelistedToken() modifier, therefore at least if the Borrower can't repay, they also can't be liquidated.

Now secondly please consider [Collateral Pause Stops Existing Repayment & Liquidation](https://dacian.me/lending-borrowing-defi-attacks#heading-collateral-pause-stops-existing-repayment-andamp-liquidation), a [high finding](https://github.com/sherlock-audit/2022-11-isomorph-judging/issues/57) from Sherlock's Isomorph Audit. In this audit it was judged that if governance disallowed a previously allowed token and if this causes *existing* positions to not be able to be repaid & liquidated, this was also a *high* finding, as governance disallowing a token should only apply to *new* positions, but existing positions should be allowed to continue to be repaid and liquidated, even if the token is no longer approved by governance.

So ideally neither repay() nor liquidate() would have onlyWhitelistedToken() - this is fair to all market participants and is the most consistent fix in line with the precedent set by the judging in Sherlock's Isomorph audit. I have submitted as High since that is what Sherlock's Isomorph audit classified the same bug. If my submission is downgraded to medium, kindly please explain why the same issue was High in Isomorph but is only medium here.

My submission actually combines 2 distinct issues which have been recognized separately in previous Sherlock competitions:

* Borrower can't repay but can be liquidated
* Governance token disallow prevents existing positions from repay (and in other contests from liquidation)

However because the primary goal of the audit is to benefit the sponsor, and because the ideal solution (remove onlyWhitelistedToken() from repay()) resolves both issues, I have combined them into this single issue to keep all discussion concentrated in the one place. I do hope that this won't disadvantage me in judging, and at the very least combining both issues into one submission should uphold this submission as a high finding.



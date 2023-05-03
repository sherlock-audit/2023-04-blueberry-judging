cducrest-brainbot

medium

# AuraSpell openPositionFarm does not join pool

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

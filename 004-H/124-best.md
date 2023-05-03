0x52

medium

# ConvexSpell#closePositionFarm removes liquidity without any slippage protection

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
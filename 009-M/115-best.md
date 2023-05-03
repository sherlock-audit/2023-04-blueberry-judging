0x52

high

# BlueBerryBank#getPositionValue causes DOS if reward token is added that doens't have an oracle

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
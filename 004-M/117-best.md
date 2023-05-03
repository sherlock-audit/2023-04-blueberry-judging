0x52

medium

# Issue 290 from previous contest has not been fully addressed by fixes

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
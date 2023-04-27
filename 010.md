devScrooge

medium

# Accrue function is not called before executing some functions

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
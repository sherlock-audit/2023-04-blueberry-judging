Bauchibred

medium

# Potential DOS / lack of acccess to oracle price due to unhandled chainlink revert


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


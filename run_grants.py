#!/usr/bin/env python3
"""Run the entitlement grants workflow."""
import asyncio
import json
from tools.workflow import analyze_csv_for_entitlements, execute_user_grants

async def main():
    # Step 1: Analyze CSV (caches it)
    print('Step 1: Analyzing CSV...')
    result = await analyze_csv_for_entitlements({'filename': 'test_data/finance_core_access_report.csv'})
    print(result)
    print()
    
    # Step 2: Execute grants
    print('Step 2: Executing grants...')
    result = await execute_user_grants({
        'filename': 'finance_core_access_report.csv',
        'appId': '0oaunaabh8NcHmeSP1d7',
        'searchColumn': 'email'
    })
    print(result)

if __name__ == '__main__':
    asyncio.run(main())

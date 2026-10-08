#!/bin/bash
# Quick UAT script for OWASP Integration
# Tests the most critical functionality

set -e  # Exit on error

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                   🧪 Quick UAT: OWASP Integration                           ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

# Function to print test result
test_result() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✅ PASS${NC}"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}❌ FAIL${NC}"
        ((TESTS_FAILED++))
    fi
    echo
}

# Test 1: Guideline Loading
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1️⃣  Testing Guideline Loading"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python3 scripts/test_guidelines_standalone.py > /tmp/uat_guidelines.log 2>&1
if grep -q "Loaded 101 guidelines" /tmp/uat_guidelines.log; then
    echo "   ✓ All 101 OWASP guidelines loaded"
    test_result 0
else
    echo "   ✗ Expected 101 guidelines"
    cat /tmp/uat_guidelines.log | head -20
    test_result 1
fi

# Test 2: Unit Tests
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "2️⃣  Running Unit Tests"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if uv run pytest tests/unit/security/ -v --tb=short > /tmp/uat_tests.log 2>&1; then
    echo "   ✓ All unit tests passed"
    grep "passed" /tmp/uat_tests.log | tail -1
    test_result 0
else
    echo "   ✗ Some tests failed"
    cat /tmp/uat_tests.log | tail -20
    test_result 1
fi

# Test 3: Category Distribution
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "3️⃣  Verifying Category Distribution"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python3 -c "
from mcp_security_review.security.guidelines import SecurityGuidelinesLoader
loader = SecurityGuidelinesLoader()
categories = loader.get_all_categories()
print(f'   ✓ Found {len(categories)} categories')
for cat in sorted(categories):
    count = len(loader.get_guidelines_by_category(cat))
    print(f'     - {cat}: {count} guidelines')
" > /tmp/uat_categories.log 2>&1

if [ $? -eq 0 ]; then
    cat /tmp/uat_categories.log
    test_result 0
else
    echo "   ✗ Category check failed"
    cat /tmp/uat_categories.log
    test_result 1
fi

# Test 4: Search Functionality
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "4️⃣  Testing Search Functionality"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python3 -c "
from mcp_security_review.security.guidelines import SecurityGuidelinesLoader
loader = SecurityGuidelinesLoader()

# Test JWT search
jwt_results = loader.search_guidelines('jwt')
print(f'   ✓ JWT search: {len(jwt_results)} results')

# Test SQL search
sql_results = loader.search_guidelines('sql')
print(f'   ✓ SQL search: {len(sql_results)} results')

# Test authentication search
auth_results = loader.search_guidelines('authentication')
print(f'   ✓ Authentication search: {len(auth_results)} results')

assert len(jwt_results) > 0, 'JWT search should return results'
assert len(sql_results) > 0, 'SQL search should return results'
assert len(auth_results) > 0, 'Auth search should return results'
print('   ✓ All searches returned results')
" > /tmp/uat_search.log 2>&1

if [ $? -eq 0 ]; then
    cat /tmp/uat_search.log
    test_result 0
else
    echo "   ✗ Search test failed"
    cat /tmp/uat_search.log
    test_result 1
fi

# Test 5: Priority Filtering
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "5️⃣  Testing Priority Filtering"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python3 -c "
from mcp_security_review.security.guidelines import SecurityGuidelinesLoader
loader = SecurityGuidelinesLoader()

critical = len(loader.get_guidelines_by_priority('critical'))
high = len(loader.get_guidelines_by_priority('high'))
medium = len(loader.get_guidelines_by_priority('medium'))
low = len(loader.get_guidelines_by_priority('low'))

print(f'   ✓ Critical: {critical} guidelines')
print(f'   ✓ High: {high} guidelines')
print(f'   ✓ Medium: {medium} guidelines')
print(f'   ✓ Low: {low} guidelines')
print(f'   ✓ Total: {critical + high + medium + low} guidelines')

assert critical > 0, 'Should have critical guidelines'
assert high > 0, 'Should have high priority guidelines'
" > /tmp/uat_priority.log 2>&1

if [ $? -eq 0 ]; then
    cat /tmp/uat_priority.log
    test_result 0
else
    echo "   ✗ Priority filtering failed"
    cat /tmp/uat_priority.log
    test_result 1
fi

# Test 6: Security Assessment
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "6️⃣  Testing Security Assessment"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python3 -c "
from mcp_security_review.security import SecurityAssessment

# Test authentication ticket
ticket = {
    'summary': 'Implement JWT authentication',
    'description': 'Add JWT token-based authentication with OAuth2',
    'fields': {
        'issuetype': {'name': 'Story'},
        'labels': ['authentication', 'security']
    }
}

assessment = SecurityAssessment()
result = assessment.assess_ticket(ticket)

print(f'   ✓ Risk Level: {result.risk_level}')
print(f'   ✓ Categories: {len(result.security_categories)} detected')
print(f'   ✓ Guidelines: {len(result.guidelines)} selected')
print(f'   ✓ Technologies: {result.technologies}')

assert result.risk_level in ['low', 'medium', 'high', 'critical']
assert len(result.guidelines) > 0, 'Should select guidelines'
print('   ✓ Security assessment working correctly')
" > /tmp/uat_assessment.log 2>&1

if [ $? -eq 0 ]; then
    cat /tmp/uat_assessment.log
    test_result 0
else
    echo "   ✗ Security assessment failed"
    cat /tmp/uat_assessment.log
    test_result 1
fi

# Test 7: Custom Guideline Helper
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "7️⃣  Testing Custom Guideline Helper"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Test the helper script exists and is executable
if [ -x scripts/add_custom_guideline.py ]; then
    echo "   ✓ Helper script exists and is executable"

    # Test auto-detection functions
    python3 -c "
import sys
sys.path.insert(0, 'scripts')
from add_custom_guideline import infer_category, infer_priority, extract_keywords

# Test category inference
cat = infer_category('API Security', 'REST API rate limiting and authentication')
print(f'   ✓ Category inference: {cat}')

# Test priority inference
pri = infer_priority('Critical SQL Injection', 'SQL injection vulnerability found')
print(f'   ✓ Priority inference: {pri}')

# Test tag extraction
tags = extract_keywords('JWT authentication with OAuth2 and API security')
print(f'   ✓ Tag extraction: {len(tags)} tags')

assert cat in ['api_security', 'authentication'], f'Unexpected category: {cat}'
assert pri in ['critical', 'high'], f'Unexpected priority: {pri}'
assert len(tags) > 0, 'Should extract tags'
print('   ✓ Auto-detection working correctly')
" > /tmp/uat_helper.log 2>&1

    if [ $? -eq 0 ]; then
        cat /tmp/uat_helper.log
        test_result 0
    else
        echo "   ✗ Helper script test failed"
        cat /tmp/uat_helper.log
        test_result 1
    fi
else
    echo "   ✗ Helper script not found or not executable"
    test_result 1
fi

# Summary
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                              📊 UAT SUMMARY                                  ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo
echo "Tests Passed: ${GREEN}${TESTS_PASSED}${NC}"
echo "Tests Failed: ${RED}${TESTS_FAILED}${NC}"
echo

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✅ ALL TESTS PASSED!${NC}"
    echo
    echo "🎉 OWASP Integration is ready for use!"
    echo
    echo "Next steps:"
    echo "  1. Review the documentation in docs/"
    echo "  2. Try adding a custom guideline"
    echo "  3. Try a security review on a real task"
    echo
    exit 0
else
    echo -e "${RED}❌ SOME TESTS FAILED${NC}"
    echo
    echo "Please review the logs in /tmp/uat_*.log"
    echo "Fix the issues and run the UAT again."
    echo
    exit 1
fi

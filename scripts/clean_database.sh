#!/bin/bash
# TenebriNET Database Cleaner
# Removes all attack data from the database and Redis cache
# Useful for clearing test data or starting fresh

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== TenebriNET Database Cleaner ===${NC}"
echo ""
echo "This will delete ALL attack data from the database."
echo "Tables to be cleared:"
echo "  - attacks"
echo "  - sessions"
echo "  - credentials"
echo "  - redis cache"
echo ""

read -p "Are you sure? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo -e "${YELLOW}Aborted.${NC}"
    exit 0
fi

echo -e "${YELLOW}Clearing database...${NC}"

# Clear PostgreSQL tables
docker exec tenebrinet-db psql -U tenebrinet -d tenebrinet -c "
DELETE FROM credentials;
DELETE FROM sessions;
DELETE FROM attacks;
" 2>/dev/null || {
    echo -e "${RED}Error: Database container not running. Run 'docker compose up -d' first.${NC}"
    exit 1
}

# Clear Redis cache
docker exec tenebrinet-redis redis-cli FLUSHALL > /dev/null 2>&1 || {
    echo -e "${RED}Error: Redis container not running.${NC}"
    exit 1
}

echo -e "${GREEN}✓ Database cleared successfully${NC}"
echo ""
echo "All test data has been removed. TenebriNET is ready for fresh data."

#!/bin/bash

# Rule Review Script
# This script captures git diff and sends it to the API for rule review
# Usage: ./rule-review.sh [base_branch] [provider]
# Environment Variables: BASE_BRANCH, PROVIDER

set -euo pipefail  # Exit on error, undefined vars, and pipe failures

# Configuration
readonly API_URL="https://circlet.ai/api/v1/rule-review"
readonly DEFAULT_BASE_BRANCH="origin/main"
readonly CURSORRULES_FILE=".cursorrules"
readonly CURSOR_RULES_DIR=".cursor/rules"
readonly RULES_SEPARATOR=$'\n---\n'
readonly MAX_DIFF_SIZE=1000000  # 1MB limit for diff content

# Color codes for better output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}ℹ️ $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️ $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}" >&2
}

# Check diff size and truncate if too large
truncate_diff_if_needed() {
    local content="$1"
    local size=${#content}
    local size_mb
    size_mb=$(awk "BEGIN {printf \"%.2f\", $size/1000000}")
    
    log_info "Diff size: ${size_mb}MB"
    
    if [[ $size -gt $MAX_DIFF_SIZE ]]; then
        log_warning "Diff size ($size bytes) exceeds limit of $MAX_DIFF_SIZE bytes"
        log_warning "Truncating diff to 1MB for API compatibility"
        log_warning "Consider breaking changes into smaller commits for complete analysis"
        
        # Truncate to MAX_DIFF_SIZE characters
        content="${content:0:$MAX_DIFF_SIZE}"
        
        # Add truncation notice to the end
        content+="\n\n[TRUNCATED: Original diff was larger than 1MB limit]"
        
        local new_size=${#content}
        log_info "Diff truncated to: $new_size bytes"
    fi
    
    echo "$content"
}

# Get git diff content
get_git_diff() {
    local base_branch="${1:-$DEFAULT_BASE_BRANCH}"
    local diff_content
    
    log_info "Getting git diff against $base_branch..."
    
    # Define files to exclude from diff (lock files and auto-generated files)
    local exclude_patterns=(
        ":(exclude)yarn.lock"
        ":(exclude)package-lock.json"
        ":(exclude)pnpm-lock.yaml"
        ":(exclude)Cargo.lock"
        ":(exclude)Gemfile.lock"
        ":(exclude)composer.lock"
        ":(exclude)poetry.lock"
        ":(exclude)Pipfile.lock"
        ":(exclude)go.sum"
        ":(exclude)*.min.js"
        ":(exclude)*.min.css"
        ":(exclude)dist/*"
        ":(exclude)build/*"
        ":(exclude)node_modules/*"
    )
    
    # Try to get diff against base branch
    if diff_content=$(git diff "$base_branch"...HEAD -- "${exclude_patterns[@]}" 2>/dev/null) && [[ -n "$diff_content" ]]; then
        echo "$diff_content"
        return 0
    fi
    
    # Fallback to previous commit
    log_warning "No diff found against $base_branch, trying HEAD~1..."
    if diff_content=$(git diff HEAD~1 -- "${exclude_patterns[@]}" 2>/dev/null) && [[ -n "$diff_content" ]]; then
        echo "$diff_content"
        return 0
    fi
    
    log_error "No git diff content found"
    return 1
}

# Read rules from .cursorrules file
read_cursorrules_file() {
    if [[ -f "$CURSORRULES_FILE" ]]; then
        log_info "Found $CURSORRULES_FILE file"
        cat "$CURSORRULES_FILE"
        return 0
    fi
    return 1
}

# Read rules from .cursor/rules directory
read_cursor_rules_dir() {
    local rule_content=""
    
    if [[ ! -d "$CURSOR_RULES_DIR" ]]; then
        return 1
    fi
    
    log_info "Found $CURSOR_RULES_DIR directory"
    
    # Process each file in the directory
    local files_found=false
    for rule_file in "$CURSOR_RULES_DIR"/*; do
        if [[ -f "$rule_file" ]]; then
            files_found=true
            local filename
            filename=$(basename "$rule_file")
            log_info "Processing rule file: $filename"
            
            # Add separator if not first file
            [[ -n "$rule_content" ]] && rule_content+="$RULES_SEPARATOR"
            
            # Add filename header and content
            rule_content+="# Rules from: $filename"$'\n'
            rule_content+=$(cat "$rule_file")
        fi
    done
    
    if [[ "$files_found" == true ]]; then
        echo "$rule_content"
        return 0
    fi
    
    return 1
}

# Combine all rules content
get_combined_rules() {
    local combined_rules=""
    
    # Read .cursorrules file
    if cursorrules_content=$(read_cursorrules_file); then
        combined_rules="$cursorrules_content"
    fi
    
    # Read .cursor/rules directory
    if cursor_rules_content=$(read_cursor_rules_dir); then
        # Add separator if we already have content
        [[ -n "$combined_rules" ]] && combined_rules+="$RULES_SEPARATOR"
        combined_rules+="$cursor_rules_content"
    fi
    
    if [[ -z "$combined_rules" ]]; then
        log_warning "No rules found in $CURSORRULES_FILE or $CURSOR_RULES_DIR"
        combined_rules="No rules file found"
    else
        log_success "Combined rules content prepared"
    fi
    
    local rules_size=${#combined_rules}
    local rules_size_mb
    rules_size_mb=$(awk "BEGIN {printf \"%.2f\", $rules_size/1000000}")
    log_info "Rules size: ${rules_size_mb}MB"
    
    echo "$combined_rules"
}

# Format API response based on compliance status
format_api_response() {
    local response_body="$1"
    
    # Check if response is valid JSON
    if ! echo "$response_body" | jq . >/dev/null 2>&1; then
        log_warning "Invalid JSON response, showing raw response:"
        echo "$response_body"
        return 0
    fi
    
    # Extract isRuleCompliant field (fix the logic bug)
    local is_compliant
    is_compliant=$(echo "$response_body" | jq -r '.isRuleCompliant')
    
    # Handle null or missing field as compliant
    if [[ "$is_compliant" == "null" || -z "$is_compliant" ]]; then
        is_compliant="true"
    fi
    
    if [[ "$is_compliant" == "false" ]]; then
        log_error "Rules violations found:"
        echo
        
        # Extract and format violations with enhanced details
        local violations_exist
        violations_exist=$(echo "$response_body" | jq -r '.relatedRules.violations | length > 0')
        
        if [[ "$violations_exist" == "true" ]]; then
            # Process each violation
            echo "$response_body" | jq -r '.relatedRules.violations[] | 
                "📋 Rule: \(.rule)\n" +
                "💡 Reason: \(.reason)\n" +
                "🎯 Confidence Score: \(.confidenceScore)/10\n" +
                (if .violationInstances and (.violationInstances | length > 0) then
                    "\n🔍 Violation Details:\n" +
                    (.violationInstances | group_by(.file) | map(
                        "• File: " + .[0].file + "\n• Line(s): [" + (map(.lineNumbersInDiff | join(", ")) | join(", ")) + "]\n\n" +
                        (map(
                            .violatingCodeSnippet +
                            (if .explanationOfViolation then "\n↳ " + .explanationOfViolation + "\n" else "" end)
                        ) | join(""))
                    ) | join("\n\n" + ("-" * 60) + "\n\n"))
                else
                    ""
                end) +
                "\n" + ("=" * 80) + "\n"
            '
        else
            echo "Rule violations detected but no details provided"
        fi
          
        # Return failure to fail the job
        return 1
    fi
    
    log_success "All rules are compliant."
    
    return 0
}

# Create and send API request
send_api_request() {
    local diff_content="$1"
    local rules_content="$2"
    local provider="$3"
    
    log_info "Creating JSON payload..."
    
    # Create JSON payload using jq for proper escaping
    local json_payload
    if ! json_payload=$(printf '%s\0%s\0%s\0%s' "$diff_content" "$rules_content" "Violations" "$provider" | \
        jq -Rs '
            split("\u0000") as [$changeSet, $rules, $filterBy, $provider] |
            {changeSet: $changeSet, rules: $rules, filterBy: $filterBy, provider: $provider}
        '); then
        log_error "Failed to create JSON payload"
        return 1
    fi
    
    log_info "Sending request to API..."
    
    local payload_size=${#json_payload}
    local payload_size_mb
    payload_size_mb=$(awk "BEGIN {printf \"%.2f\", $payload_size/1000000}")
    log_info "Payload size: ${payload_size_mb}MB"
    
    # Send request and capture response with status
    local response
    if ! response=$(echo "$json_payload" | curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST \
        -H "Content-Type: application/json" \
        -d @- \
        "$API_URL" 2>/dev/null); then
        log_error "Failed to send API request"
        return 1
    fi
    
    # Parse response
    local http_status response_body
    http_status=$(echo "$response" | grep "HTTP_STATUS:" | cut -d: -f2)
    response_body=$(echo "$response" | sed '/HTTP_STATUS:/d')
    
    # Check status code first
    if [[ "$http_status" -ge 200 && "$http_status" -lt 300 ]]; then
        log_success "Rule review request completed successfully"
        
        # Format the response based on compliance status
        # This will return 1 if violations are found, 0 if compliant
        if ! format_api_response "$response_body"; then
            return 1  # Propagate failure from format_api_response
        fi
        return 0
    else
        log_error "Rule review request failed with status: $http_status"
        echo "Raw API Response:"
        echo "$response_body"
        return 1
    fi
}

# Display content with borders
display_content() {
    local title="$1"
    local content="$2"
    
    echo
    echo "$title"
    printf '=%.0s' {1..50}
    echo
    echo "$content"
    printf '=%.0s' {1..50}
    echo
    echo
}

# Main execution
main() {
    local base_branch="${BASE_BRANCH:-${1:-$DEFAULT_BASE_BRANCH}}"
    local provider="${PROVIDER:-${2:-openai}}"
    
    log_info "Starting rule review process with provider: $provider..."
    
    # Get git diff
    local diff_content
    if ! diff_content=$(get_git_diff "$base_branch"); then
        log_success "No changes found - nothing to review!"
        log_info "Rule review completed successfully (no diff to analyze)"
        exit 0
    fi
    
    # Check diff size and truncate if too large
    diff_content=$(truncate_diff_if_needed "$diff_content")
    
    display_content "Git Diff Content:" "$diff_content"
    
    # Get combined rules
    local rules_content
    rules_content=$(get_combined_rules)
    
    # Check if no rules were found
    if [[ "$rules_content" == "No rules file found" ]]; then
        log_success "No rules found - skipping rule review!"
        log_info "💡 Please create cursor rules to enable automated rule checking:"
        log_info "   • Create a .cursorrules file in your project root, or"
        log_info "   • Add rule files to the .cursor/rules/ directory"
        log_info "Rule review completed successfully (no rules to check against)"
        exit 0
    fi
    
    display_content "Combined Rules Content:" "$rules_content"
    
    # Send API request
    if ! send_api_request "$diff_content" "$rules_content" "$provider"; then
        exit 1
    fi
}

# Check dependencies
check_dependencies() {
    local missing_deps=()
    
    command -v git >/dev/null 2>&1 || missing_deps+=("git")
    command -v jq >/dev/null 2>&1 || missing_deps+=("jq")
    command -v curl >/dev/null 2>&1 || missing_deps+=("curl")
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        log_info "Please install the missing dependencies and try again"
        exit 1
    fi
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    check_dependencies
    main "$@"
fi 
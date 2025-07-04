Be sure to work with Gemini based on the GEMINI_INTEGRATION_STRATEGY.md under docs/planning directory.

# Daily Work Log Protocol

## End-of-Day Workflow
Before ending any development session, ALWAYS suggest creating:

### 1. Today's TASK Documentation
- **File**: `worklog/tasks/TASK_YYYY-MM-DD_DESCRIPTION.md`
- **Content**: Detailed summary of today's work including:
  - What was accomplished
  - Technical decisions made and rationale
  - Blockers encountered and solutions
  - Code changes and their purpose
  - Integration points and testing results
  - References to commits, files, and external resources

### 2. Tomorrow's TODO Planning
- **File**: `worklog/tasks/TODO_YYYY-MM-DD.md` (next day's date)
- **Content**: Actionable items for next session including:
  - Priority tasks and objectives
  - Dependencies and prerequisites
  - Time estimates and deadlines
  - Context needed to resume work effectively
  - Links to relevant documentation and code

### 3. Session Logs
- **Update**: `worklog/logs/activity.log` with session summary
- **Record**: Any validation results in `worklog/logs/validation.log`
- **Note**: Key decisions and architectural changes

## Workflow Template Reminder
Use this structure for end-of-day suggestions:

```markdown
## 📝 End-of-Day Work Log

Before we wrap up today's session, let me suggest creating:

### 1. Today's TASK Documentation
- **`worklog/tasks/TASK_2025-07-04_STEP3_COMPLETION.md`**
- Document: [specific accomplishments]
- Include: [technical decisions and rationale]

### 2. Tomorrow's TODO Planning  
- **`worklog/tasks/TODO_2025-07-05.md`**
- Priority 1: [most important next task]
- Priority 2: [secondary objectives]
- Context: [what's needed to resume effectively]

### 3. Session Summary
- Update activity logs with today's progress
- Record any validation results or performance metrics
- Note architectural decisions for future reference
```

This ensures project continuity and maintains the valuable development history that helps with debugging, onboarding, and academic documentation.

# Research and Planning Collaboration Protocol

## Gemini Integration for Research Discussions
When discussing vulnerability research, planning, or strategic decisions, ALWAYS:

### 1. Consult Gemini for Additional Perspectives
- **When**: During any research discussion, architecture planning, or strategic decision making
- **How**: Use Gemini integration to get alternative viewpoints and suggestions
- **Focus Areas**:
  - Vulnerability discovery methods and novel approaches
  - Architecture design and system integration decisions  
  - Research methodology and academic contributions
  - Performance optimization and scalability considerations
  - Security implications and threat modeling
  - Implementation strategies and technology choices

### 2. Present Comprehensive Options
After gathering Gemini's input, present:
- **Claude's Analysis**: My technical assessment and recommendations
- **Gemini's Perspective**: Alternative viewpoints and suggestions from Gemini
- **Comparative Analysis**: Pros/cons of different approaches
- **Decision Framework**: Clear criteria for evaluation
- **Recommendation**: Synthesized recommendation based on all inputs

### 3. Collaboration Template
Use this structure for research discussions:

```markdown
## 🔬 Research Discussion: [Topic]

### Claude's Analysis
- Technical assessment: [my analysis]
- Recommended approach: [my recommendation]
- Implementation considerations: [technical details]

### Gemini's Perspective  
[Consult Gemini for alternative viewpoints]
- Alternative approaches suggested: [Gemini's input]
- Different considerations raised: [additional factors]
- Novel ideas or methods: [creative suggestions]

### Comparative Analysis
| Approach | Pros | Cons | Feasibility | Impact |
|----------|------|------|-------------|--------|
| Claude's | ... | ... | ... | ... |
| Gemini's | ... | ... | ... | ... |
| Hybrid | ... | ... | ... | ... |

### Decision Framework
- Technical feasibility: [evaluation criteria]
- Research novelty: [academic contribution potential]  
- Implementation effort: [resource requirements]
- Performance impact: [expected improvements]
- Budget considerations: [cost implications]

### Synthesized Recommendation
[Combined recommendation incorporating best elements from both perspectives]
```

## Research Areas for Collaboration
Especially important for:
- **Novel Vulnerability Discovery**: New methods and approaches
- **Architecture Decisions**: System design and integration strategies
- **Performance Optimization**: Scalability and efficiency improvements
- **Academic Contributions**: Research methodology and publication potential
- **Technology Selection**: Framework and tool choices
- **Security Analysis**: Threat modeling and defensive strategies

This ensures comprehensive analysis by leveraging both Claude's technical expertise and Gemini's alternative perspectives for better decision making.

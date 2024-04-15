The following is a flowchart of the release workflows...

```mermaid
---
title: Create Release PR Workflow
---

flowchart TB
    Start[Create Release PR] --> ManualDispatch{Manual Dispatch}
    Start --> OnSchedule[On Schedule - Once a day]
    ManualDispatch --> GetACAPYRelease[Get latest ACA-PY Release via PIP]
    ManualDispatch --> |Re-Release|UpdateGlobal
    OnSchedule --> GetACAPYRelease
    GetACAPYRelease --> CheckGlobal[Get Global Repo Version]
    CheckGlobal --> Compare{Compare versions}
    Compare --> |Match| End
    Compare --> |No Match| UpdateGlobal[Update Global Repo Version]
    UpdateGlobal --> UpdateAllPlugins[Update All Plugins]
    UpdateAllPlugins --> RunLintChecks[Run Lint Checks]
    RunLintChecks --> RunUnitTests[Run Unit Tests]
    RunUnitTests --> RunIntegrationTests[Run Integration Tests]
    RunIntegrationTests --> RemoveFailedPlugins[Remove Failed Plugins From Change Set]
    RemoveFailedPlugins --> CreateReleaseNotes[Create Release Notes]
    CreateReleaseNotes --> CreateReleasePR[Create Release PR]

```

```mermaid
---
title: Create Release Workflow
---

flowchart TB
    Start[Create Release] --> OnPushMain[On Push to Main]
    OnPushMain --> GetACAPYRelease[Get latest ACA-PY Release via PIP]
    GetACAPYRelease --> CheckChangeSet{Check ACAPY Version in Change Set}
    CheckChangeSet --> |No updated lock files| End
    CheckChangeSet --> |Updated lock files| ConfigureGit[Configure Git]
    ConfigureGit --> GetReleaseTags[Get Release Tags - Based on ACA-PY Version]
    GetReleaseTags --> TagsExist{Tags Exist}
    TagsExist --> |Yes| IncrementPatch[Increment Patch]
    TagsExist --> |No| CreateTagOnACAPYVersion[Increment Minor]
    IncrementPatch --> GetReleaseNotes[Get Release Notes and Plugins That Updated]
    CreateTagOnACAPYVersion --> GetReleaseNotes
    GetReleaseNotes --> CreateReleaseBranch[Create Release Branch]

```
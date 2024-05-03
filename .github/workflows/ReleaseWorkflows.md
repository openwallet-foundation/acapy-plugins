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
    OnPushMain --> ChangedPoetryFiles{Changed poetry.lock Files?}
    ChangedPoetryFiles --> |No| End
    ChangedPoetryFiles --> |Yes| ConfigureGit[Configure Git]
    ConfigureGit --> GetReleaseTags[Get Release Tags - Based on ACA-PY Version]
    GetReleaseTags --> TagsExist{Tags Exist}
    TagsExist --> |Yes| IncrementPatch[Increment Patch Version. Ex: 1.0.0 -> 1.0.0.1 or 1.0.0.1 -> 1.0.0.2]
    TagsExist --> |No| CreateTagOnACAPYVersion[Create Tag on ACA-PY Version]
    IncrementPatch --> GetReleaseNotes[Get Release Notes and Plugins That Updated]
    CreateTagOnACAPYVersion --> GetReleaseNotes
    GetReleaseNotes --> CreateRelease[Create Release]

```
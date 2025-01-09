ToolingExecutable
================

Running via Visual Studio F5/local debugging
------------
The ToolingExecutable project is set up as a regular executable project. To pass
arguments to the exe do the following:

1. Set `ToolingExecutable` as a `Startup project` if not done already.
1. Right click the `ToolingExecutable` project and select "Properties" at the bottom of the flyout.
1. Navigate to the `Debugging` section under `Configuration Properties` and set the following properties:
1. Command: `$(TargetPath)`
1. Command Arguments: This should have the arguments you want to pass to `ToolingExecutable`.
   1. e.g `"--Language" "C++" "--EdlPath" "C:\Users\Public\Documents\test.edl" "--ErrorHandling" "ErrorCode" "--OutputDirectory" "C:\Users\Public\Documents"`
1. Working Directory: `$(ProjectDir)`

### Note 1:
Code generation is still in progress. The project currently
does not generate the code yet.

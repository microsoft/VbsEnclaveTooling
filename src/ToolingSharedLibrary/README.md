ToolingSharedLibrary
================

Purpose of this shared library
------------
This is a shared library between the projects in this repository and
the `ToolingTests` project and the `ToolingExecutable` project.


*Note: This project uses the Google flatbuffers vcpkg static package inorder
to facilite marshaling data into and out of the enclave. This means we must take it as a dependency,
and you must install/integrate vcpkg into your visual studio inorder to build the project.*

Here are the instructions to integrate vcpkg into your visual studio application:

https://learn.microsoft.com/vcpkg/get_started/get-started-msbuild?pivots=shell-powershell

You only need to follow step 1 (Set up vcpkg) in the above link, then close and relaunch Visual Studio. After this
you should be able to build the entire repository without issue.

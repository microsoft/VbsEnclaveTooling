// Copyright(c) Microsoft Corporation.
// Licensed under the MIT License.

#include <pch.h>
#include "CppUnitTest.h"
#include <VbsEnclaveSDK.h>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace VbsEnclaveSDKTests
{
	TEST_CLASS(VbsEnclaveSDKTests)
	{
	public:

		TEST_METHOD(RunAddTwoNumsTest)
		{
            Assert::AreEqual(4U, AddTwoNums_SDK_Func(2, 2));
		}
	};
}

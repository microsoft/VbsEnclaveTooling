// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once 
#include <array>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <vector>
#include <wil/result_macros.h>
#include <VbsEnclaveABI\Shared\VbsEnclaveAbiBase.h>

// All types and functions within this file should be usable within both the hostApp and the enclave.
namespace VbsEnclaveABI::Shared::Converters
{
    // Base for all generated struct metadata.
    template <typename T>
    struct StructMetadata;

    struct AbiRegisterVtl0Callbacks_args
    {
        std::vector<std::uint64_t> m_callback_addresses;
        std::vector<std::string> m_callback_names;
        std::int32_t m__return_value_;
    };

    template <>
    struct StructMetadata<AbiRegisterVtl0Callbacks_args>
    {
        static constexpr auto members = std::make_tuple(
            &AbiRegisterVtl0Callbacks_args::m_callback_addresses,
            &AbiRegisterVtl0Callbacks_args::m_callback_names,
            &AbiRegisterVtl0Callbacks_args::m__return_value_);
    };

    // Type traits
    template<typename T>
    struct is_unique_ptr : std::false_type {};

    template<typename T, typename D>
    struct is_unique_ptr<std::unique_ptr<T, D>> : std::true_type {};

    template<typename T>
    struct unique_ptr_inner_type { using type = void; };

    template<typename T, typename D>
    struct unique_ptr_inner_type<std::unique_ptr<T, D>> { using type = std::decay_t<T>; };

    template<typename T>
    using unique_ptr_inner_type_t = typename unique_ptr_inner_type<std::decay_t<T>>::type;

    template <typename T>
    constexpr bool is_unique_ptr_v = is_unique_ptr<std::decay_t<T>>::value;

    template <typename T>
    struct is_optional : std::false_type {};

    template <typename T>
    struct is_optional<std::optional<T>> : std::true_type {};

    template <typename T>
    struct optional_inner_type { using type = void; };

    template <typename T>
    struct optional_inner_type<std::optional<T>> { using type = std::decay_t<T>; };

    template<typename T>
    using optional_inner_type_t = typename optional_inner_type<std::decay_t<T>>::type;

    template <typename T>
    constexpr bool is_optional_v = is_optional<std::decay_t<T>>::value;

    template <typename T>
    struct is_vector : std::false_type {};

    template <typename T, typename Alloc>
    struct is_vector<std::vector<T, Alloc>> : std::true_type {};

    template <typename T>
    struct vector_inner_type { using type = void; };

    template <typename T, typename Alloc>
    struct vector_inner_type<std::vector<T, Alloc>> { using type = std::decay_t<T>; };

    template<typename T>
    using vector_inner_type_t = typename vector_inner_type<std::decay_t<T>>::type;

    template <typename T>
    constexpr bool is_vector_v = is_vector<T>::value;

    template <typename T>
    struct is_std_array : std::false_type {};

    template <typename T, std::size_t N>
    struct is_std_array<std::array<T, N>> : std::true_type {};

    template <typename T>
    struct std_array_inner_type { using type = void; };

    template <typename T, std::size_t N>
    struct std_array_inner_type<std::array<T, N>> { using type = std::decay_t<T>; };

    template<typename T>
    using std_array_inner_type_t = typename std_array_inner_type<std::decay_t<T>>::type;

    template <typename T>
    struct is_container_type : std::false_type {};

    template <>
    struct is_container_type<std::string> : std::true_type {};

    template <>
    struct is_container_type<std::wstring> : std::true_type {};

    template <typename U, typename Alloc>
    struct is_container_type<std::vector<U, Alloc>> : std::true_type {};

    template <typename U, std::size_t N>
    struct is_container_type<std::array<U, N>> : std::true_type {};

    template <typename T>
    constexpr bool is_container_v = is_container_type<T>::value;

    template <typename T>
    constexpr bool is_std_array_v = is_std_array<T>::value;

    template <typename T>
    using remove_pointer_t = typename std::remove_pointer<T>::type;

    template <typename T>
    struct vector_or_array_inner_type
    {
        static_assert(
            std::is_same_v<T, void>,
            "vector_or_array_inner_type<T>: T must be std::vector or std::array"
        );
    };

    template <typename T, typename Alloc>
    struct vector_or_array_inner_type<std::vector<T, Alloc>> { using type = std::decay_t<T>; };

    template <typename T, std::size_t N>
    struct vector_or_array_inner_type<std::array<T, N>> { using type = std::decay_t<T>; };

    template <typename T>
    using vector_or_array_inner_type_t = typename vector_or_array_inner_type<std::decay_t<T>>::type;

    template<typename T>
    struct is_function_ptr : std::false_type {};

    template<typename T>
    struct is_function_ptr<T*> : std::is_function<T> {};

    template<typename T>
    constexpr bool is_function_ptr_v = is_function_ptr<std::decay_t<T>>::value;

    template<typename T, typename = void>
    struct FunctionInfo;

    template<typename ReturnT, typename... Args>
    struct FunctionInfo<ReturnT(*)(Args...), std::enable_if_t<is_function_ptr_v<ReturnT(*)(Args...)>>> {
        using ReturnType = ReturnT;
        static constexpr std::size_t NumberOfParameters = sizeof...(Args);
        template<std::size_t N>
        using arg = std::tuple_element_t<N, std::tuple<Args...>>;
    };

    template <typename T>
    constexpr bool is_raw_ptr_v = std::is_pointer_v<T>;

    template <typename T>
    constexpr bool is_structure_v =
        std::is_class_v<std::decay_t<T>> &&
        !is_unique_ptr_v<std::decay_t<T>> &&
        !is_optional_v<std::decay_t<T>> &&
        !is_container_v<std::decay_t<T>>;

    template <typename T, typename U>
    constexpr bool are_both_arithmetic_v = std::is_arithmetic_v<T> && std::is_arithmetic_v<U>;

    template <typename T, typename U>
    constexpr bool are_both_enums_v = std::is_enum_v<T> && std::is_enum_v<U>;

    template <typename T, typename U>
    constexpr bool are_both_same_v = std::is_same_v<T, U>;

    template <typename T, typename U>
    constexpr bool are_both_structures_v = is_structure_v<T> && is_structure_v<U>;

    // Used only for static_asserts
    template<typename...> struct always_false : std::false_type {};

    template <
        template<typename...> class Wrapper,
        typename TargetInnerType,
        typename Src,
        typename ConvertFunc
    >
    auto ConvertToWrapper(const Src& src, ConvertFunc&& conversion_func)
    {
        if constexpr (is_unique_ptr_v<Src> || is_raw_ptr_v<Src> || is_optional_v<Src>)
        {
            if (!src)
            {
                return Wrapper<TargetInnerType>{};
            }

            return conversion_func(*src);
        }
        else if constexpr (is_structure_v<Src>)
        {
            return conversion_func(src);
        }
        else
        {
            static_assert(always_false<Src>::value, "Unsupported src type for ConvertToWrapper.");
        }
    }

    template <typename Target, typename Src>
    inline Target ConvertType(const Src& src);

    template <typename Target, typename Src>
    inline std::enable_if_t<is_unique_ptr_v<Target>, Target> ConvertToUniquePtr(const Src& src)
    {
        using TargetInnerType = unique_ptr_inner_type_t<Target>;

        auto conversion_func = [] (auto&& value)
        {
            return std::make_unique<TargetInnerType>(ConvertType<TargetInnerType>(value));
        };

        return ConvertToWrapper<std::unique_ptr, TargetInnerType>(src, std::move(conversion_func));
    }

    template <typename Target, typename Src>
    inline std::enable_if_t<is_optional_v<Target>, Target> ConvertToOptional(const Src& src)
    {
        using TargetInnerType = optional_inner_type_t<Target>;

        auto conversion_func = [] (auto&& value)
        {
            return std::make_optional<TargetInnerType>(ConvertType<TargetInnerType>(value));
        };

        return ConvertToWrapper<std::optional, TargetInnerType>(src, std::move(conversion_func));
    }

    template<typename T>
    inline std::wstring ConvertToStdWString(const T& wstr)
    {
        if constexpr (is_unique_ptr_v<T>)
        {
            if (!wstr)
            {
                return {};
            }

            return std::wstring(wstr->wchars.begin(), wstr->wchars.end());
        }
        else
        {
            return std::wstring(wstr.wchars.begin(), wstr.wchars.end());
        }
    }

    template<typename Target>
    inline Target CreateWStringT(const std::wstring& wchars)
    {
        using DecayedType = std::decay_t<Target>;
        if constexpr (is_unique_ptr_v<DecayedType>)
        {
            using InnerType = unique_ptr_inner_type_t<DecayedType>;
            auto ptr = std::make_unique<InnerType>();
            ptr->wchars.assign(wchars.begin(), wchars.end());
            return ptr;
        }
        else if constexpr (is_structure_v<DecayedType>)
        {
            DecayedType wcharT {};
            wcharT.wchars.assign(wchars.begin(), wchars.end());
            return wcharT;
        }
        else
        {
            static_assert(always_false<Target>::value, "CreateWStringT: Unsupported Target (must be unique_ptr or struct)");
        }
    }

    template <typename TargetContainer, typename SrcContainer, typename ConvertFunc>
    std::enable_if_t<is_vector_v<TargetContainer>, TargetContainer> TransformRangeToContainer(const SrcContainer& src, ConvertFunc&& conversion_func)
    {
        TargetContainer target_vector;
        target_vector.reserve(src.size());
        for (const auto& value : src)
        {
            target_vector.emplace_back(conversion_func(value));
        }

        return target_vector;
    }

    template <typename TargetContainer, typename SrcContainer, typename ConvertFunc>
    std::enable_if_t<is_std_array_v<TargetContainer>, TargetContainer> TransformRangeToContainer(const SrcContainer& src, ConvertFunc&& conversion_func)
    {
        TargetContainer arr {};

        // We can't static_assert because the SrcContainer size is only known at runtime. However, we know that in this conversion
        // layer that the SrcContainer should always be the same size as the array. If it's not then something is wrong.
        FAIL_FAST_HR_IF_MSG(E_INVALIDARG, arr.size() != src.size(), "Array size: %zu, SrcContainer size: %zu", arr.size(), src.size());

        for (size_t i = 0; i < arr.size(); ++i)
        {
            arr[i] = conversion_func(src[i]);
        }

        return arr;
    }

    template <typename Target, typename Src>
    inline std::enable_if_t<is_structure_v<Target>&& is_structure_v<Src>, std::decay_t<Target>> ConvertStruct(const Src& src);

    template <typename Target, typename Src>
    inline Target ConvertType(const Src& src)
    {
        using DecayedSrc = std::decay_t<Src>;
        using DecayedTarget = std::decay_t<Target>;

        if constexpr (are_both_same_v<DecayedSrc, DecayedTarget>)
        {
            return src;
        }
        else if constexpr (are_both_arithmetic_v<DecayedSrc, DecayedTarget>)
        {
            return src;
        }
        else if constexpr (are_both_structures_v<DecayedSrc, DecayedTarget>)
        {
            return ConvertStruct<DecayedTarget>(src);
        }
        else if constexpr (are_both_enums_v<DecayedSrc, DecayedTarget>)
        {
            return static_cast<DecayedTarget>(src);
        }
        // Convert WStringT flatbuffer src to std::wstring target. 
        else if constexpr (are_both_same_v<DecayedTarget, std::wstring>)
        {
            // The Codegen will only pass std::wstring as a target when the source is related to WStringT.
            return ConvertToStdWString(src);
        }
        // Convert std::wstring source to WStringT flatbuffer target.
        else if constexpr (are_both_same_v<DecayedSrc, std::wstring>)
        {
            // The Codegen will only pass std::wstring as a source when the target is related to WStringT.
            return CreateWStringT<DecayedTarget>(src);
        }
        else if constexpr (is_unique_ptr_v<DecayedSrc> && is_structure_v<DecayedTarget>)
        {
            if (!src)
            {
                return {};
            }

            return ConvertType<DecayedTarget>(*src);
        }
        else if constexpr (is_unique_ptr_v<DecayedTarget>)
        {
            return ConvertToUniquePtr<DecayedTarget>(src);
        }
        else if constexpr (is_optional_v<DecayedTarget>)
        {
            return ConvertToOptional<DecayedTarget>(src);
        }
        else if constexpr (is_vector_v<DecayedTarget> || is_std_array_v<DecayedTarget>)
        {
            using InnerSrcType = vector_or_array_inner_type_t<DecayedSrc>;
            using InnerTargetType = vector_or_array_inner_type_t<DecayedTarget>;
            return TransformRangeToContainer<DecayedTarget>(src, [] (const InnerSrcType& value)
            {
                return ConvertType<InnerTargetType>(value);
            });
        }
        else
        {
            static_assert(always_false<DecayedSrc, DecayedTarget>::value,
                "Conversion not found in function: " __FUNCSIG__);
        }
    }

    template <typename DecayedSrc, typename DecayedTarget>
    struct ConvertStructHelper
    {
        template<typename Src, std::size_t... I>
        static DecayedTarget apply(const Src& src, std::index_sequence<I...>)
        {
            DecayedTarget target_struct {};
            (
                (
                [&]
            {
                auto& src_field = src.*(std::get<I>(StructMetadata<DecayedSrc>::members));
                auto& dst_field = target_struct.*(std::get<I>(StructMetadata<DecayedTarget>::members));
                using DecayedSrcFieldT = std::decay_t<decltype(src_field)>;
                using DecayedTargetFieldT = std::decay_t<decltype(dst_field)>;

                dst_field = ConvertType<DecayedTargetFieldT>(src_field);
            }()
                ), ...
            );
            return target_struct;
        }
    };

    template <typename Target, typename Src>
    inline std::enable_if_t<is_structure_v<Target>&& is_structure_v<Src>, std::decay_t<Target>> ConvertStruct(const Src& src)
    {
        using DecayedSrc = std::decay_t<decltype(src)>;
        using DecayedTarget = std::decay_t<Target>;

        constexpr size_t N = std::tuple_size_v<decltype(StructMetadata<DecayedSrc>::members)>;
        static_assert(N == std::tuple_size_v<decltype(StructMetadata<DecayedTarget>::members)>,
            "Source and Target structs must have the same number of fields!");

        return ConvertStructHelper<DecayedSrc, DecayedTarget>::apply(src, std::make_index_sequence<N>{});
    }

    template<typename Src, typename Target>
    inline std::enable_if_t<is_unique_ptr_v<Src>&& is_raw_ptr_v<Target>, void> UpdateParameterValue(Src& src, Target& target)
    {
        if (src && target)
        {
            *target = std::move(*src);
        }
    }

    template<typename Src, typename Target>
    inline std::enable_if_t<are_both_same_v<Src, Target>, void> UpdateParameterValue(Src& src, Target& target)
    {
        target = std::move(src);
    }

    template<typename Expected, typename Actual>
    constexpr bool ShouldCallGet()
    {
        return false; // base case, all others should have a specialized template.
    }

    template<typename Expected, typename Actual>
    constexpr std::enable_if_t<is_raw_ptr_v<Expected>&& is_unique_ptr_v<Actual>, bool> ShouldCallGet()
    {
        return are_both_same_v<std::decay_t<remove_pointer_t<Expected>>, unique_ptr_inner_type_t<Actual>>;
    }

    template<typename Expected, typename Actual>
    constexpr decltype(auto) ConvertIfNeeded(Actual&& value)
    {
        if constexpr (ShouldCallGet<Expected, Actual>())
        {
            return value.get();
        }
        else
        {
            return value;
        }
    }

    template <typename FuncT, typename DevTypeT>
    struct CallDevImplHelper
    {
        using FuncTrait = FunctionInfo<std::decay_t<FuncT>>;

        template<std::size_t... I>
        static void apply(FuncT&& func, DevTypeT& input_args, std::index_sequence<I...>)
        {
            constexpr size_t struct_fields_size = std::tuple_size_v<decltype(StructMetadata<DevTypeT>::members)>;

            if constexpr (std::is_void_v<typename FuncTrait::ReturnType>)
            {
                static_assert(
                    struct_fields_size == FuncTrait::NumberOfParameters,
                    "For functions that return void, the number of fields in the abi struct must match the number of function parameters.");

                std::invoke(
                    std::forward<FuncT>(func),
                    ConvertIfNeeded<typename FuncTrait::template arg<I>>(input_args.*(std::get<I>(StructMetadata<DevTypeT>::members)))...
                );
            }
            else
            {
                static_assert(
                    struct_fields_size == FuncTrait::NumberOfParameters + 1,
                    "For functions that return a non void value, the number of fields in the abi struct must be one more than the number of function parameters.");

                input_args.m__return_value_ = std::invoke(
                    std::forward<FuncT>(func),
                    ConvertIfNeeded<typename FuncTrait::template arg<I>>(input_args.*(std::get<I>(StructMetadata<DevTypeT>::members)))...
                );
            }
        }
    };

    template <typename FuncT, typename DevTypeT>
    std::enable_if_t<is_function_ptr_v<FuncT>&& is_structure_v<DevTypeT>, void> CallDevImpl(FuncT&& func, DevTypeT& input_args)
    {
        using FuncTrait = FunctionInfo<std::decay_t<FuncT>>;
        CallDevImplHelper<FuncT, DevTypeT>::apply(std::forward<FuncT>(func), input_args, std::make_index_sequence<FuncTrait::NumberOfParameters>{});
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once 
#include <VbsEnclaveABI\Shared\VbsEnclaveAbiBase.h>
#include <string>
#include <memory>
#include <type_traits>
#include <stdexcept>
#undef min
#undef max
#include <algorithm>

// All types and functions within this file should be usable within both the hostApp and the enclave.
namespace VbsEnclaveABI::Shared::Converters
{
    enum class ConversionType : std::uint32_t
    {
        ToDevType,
        ToFlatbuffer
    };

    // Base for all generated struct metadata.
    template <typename T>
    struct StructMetaData;

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
    using unique_ptr_inner_type_t = unique_ptr_inner_type<std::decay_t<T>>::type;

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
    using optional_inner_type_t = optional_inner_type<std::decay_t<T>>::type;

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
    using vector_inner_type_t = vector_inner_type<std::decay_t<T>>::type;

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
    using std_array_inner_type_t = std_array_inner_type<std::decay_t<T>>::type;

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

    template<typename T>
    concept UniquePtr = is_unique_ptr_v<T>;

    template<typename T>
    concept Optional = is_optional_v<T>;

    template<typename T>
    concept Vector = is_vector_v<T>;

    template<typename T>
    concept StdArray = is_std_array_v<T>;

    template<typename T>
    concept Container = is_container_v<T>;

    template<typename T>
    concept RawPtr = std::is_pointer_v<T>;

    template<typename T>
    concept NonWrappedStruct =
        std::is_class_v<std::decay_t<T>> &&    // Must be a class or struct
        !UniquePtr<std::decay_t<T>> &&   // Must not be unique ptr
        !Optional<std::decay_t<T>> && // Must not be optional
        !Container<std::decay_t<T>>; // Must not be wstring, string, vector or array

    template <typename T, typename U>
    concept IsOptionalAndUniquePtr =
        (Optional<T> && UniquePtr<U>) ||
        (Optional<U> && UniquePtr<T>);

    template <typename T, typename U>
    concept IsUniquePtrAndNonWrappedStruct =
        (UniquePtr<T> && NonWrappedStruct<U>) ||
        (UniquePtr<U> && NonWrappedStruct<T>);

    template <typename T, typename U>
    concept IsRawPtrAndUniquePtr =
        (RawPtr<T> && UniquePtr<U>) ||
        (RawPtr<U> && UniquePtr<T>);

    template <typename T>
    concept IsRawPtrAndNonWrappedStruct = RawPtr<T> && NonWrappedStruct<remove_pointer_t<T>>;

    template <typename T>
    concept IsRawPtrAndNotNonWrappedStruct = RawPtr<T> && !NonWrappedStruct<remove_pointer_t<T>>;

    template <typename T, typename U>
    concept IsVectorAndStdArray = (Vector<T> && StdArray<U>) || (Vector<U> && StdArray<T>);

    template <typename T, typename U>
    concept AreBothUniquePtrs = UniquePtr<T> && UniquePtr<U>;

    template <typename T, typename U>
    concept AreBothArithmeticTypes = std::is_arithmetic_v<T> && std::is_arithmetic_v<U>;

    template <typename T, typename U>
    concept AreBothEnums = std::is_enum_v<T> && std::is_enum_v<U>;

    template <typename T, typename U>
    concept AreBothTheSame = std::is_same_v<T, U>;

    template <typename T, typename U>
    concept AreBothNonWrappedStructs = NonWrappedStruct<T> && NonWrappedStruct<U>;

    template <typename T, typename U>
    concept AreBothVectors = Vector<T> && Vector<U>;

    // Used only for static_asserts
    template<typename...> struct always_false : std::false_type {};

    template<ConversionType ConversionT, typename Src, typename Target>
    decltype(auto) ConvertType(const Src& src)
    {
        using DecayedSrc = std::decay_t<Src>;
        using DecayedTarget = std::decay_t<Target>;

        if constexpr (ConversionT == ConversionType::ToDevType)
        {
            return ConvertToDevType<DecayedSrc, DecayedTarget>(src);
        }
        else
        {
            return ConvertToFlatbuffer<DecayedSrc, DecayedTarget>(src);
        }
    }

    template <
        template<typename...> class Wrapper,
        typename Src,
        typename TargetInnerType,
        typename AllocFunc, 
        typename ConvertFunc
    >
    auto ConvertToWrapper(const Src& src, AllocFunc&& allocator_func, ConvertFunc&& converter_func)
    {
        using DecayedSrc = std::decay_t<Src>;

        if constexpr (UniquePtr<DecayedSrc>)
        {
            if (!src)
            {
                return Wrapper<TargetInnerType>{};
            }

            return allocator_func(converter_func(*src));
        }
        else if constexpr (Optional<DecayedSrc>)
        {
            if (!src.has_value())
            {
                return Wrapper<TargetInnerType>{};
            }

            return allocator_func(converter_func(src.value()));
        }
        else if constexpr (RawPtr<DecayedSrc>)
        {
            if (!src)
            {
                return Wrapper<TargetInnerType>{};
            }

            return allocator_func(converter_func(*src));
        }
        else if constexpr (NonWrappedStruct<DecayedSrc>)
        {
            return allocator_func(converter_func(src));
        }
        else
        {
            static_assert(always_false<Src>::value, "Unsupported src type for ConvertToWrapper.");
        }
    }

    template <ConversionType ConversionT, typename Src, UniquePtr Target>
    inline std::decay_t<Target> ConvertToUniquePtr(const Src& src)
    {
        using TargetInnerType = unique_ptr_inner_type_t<Target>;
        auto allocator_func = [] (auto&& value)
        {
            auto ptr = std::make_unique<TargetInnerType>();
            THROW_IF_NULL_ALLOC(ptr.get());
            *ptr = std::forward<decltype(value)>(value);
            return ptr;
        };

        auto converter_func = [] (auto&& value)
        {
            using SrcInnerType = std::decay_t<decltype(value)>;
            return ConvertType<ConversionT, SrcInnerType, TargetInnerType>(value);
        };

        return ConvertToWrapper<std::unique_ptr, Src, TargetInnerType>(src, allocator_func, converter_func);
    }

    template <ConversionType ConversionT, typename Src, Optional Target>
    inline std::decay_t<Target> ConvertToOptional(const Src& src)
    {
        using TargetInnerType = optional_inner_type_t<Target>;
        auto allocator_func = [] (auto&& value)
        {
            return std::make_optional<TargetInnerType>(std::forward<decltype(value)>(value));
        };

        auto converter_func = [] (auto&& value)
        {
            using SrcInnerType = std::decay_t<decltype(value)>;
            return ConvertType<ConversionT, SrcInnerType, TargetInnerType>(value);
        };

        return ConvertToWrapper<std::optional, Src, TargetInnerType>(src, allocator_func, converter_func);
    }

    template<typename T>
    inline std::wstring ConvertToStdWString(const T& wstr)
    {
        if constexpr (UniquePtr<T>)
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

    template<typename FlatbufferType>
    inline FlatbufferType CreateWStringT(const std::wstring& wchars)
    {
        using Decayed = std::decay_t<FlatbufferType>;
        if constexpr (UniquePtr<Decayed>)
        {
            using InnerType = unique_ptr_inner_type_t<Decayed>;
            auto ptr = std::make_unique<InnerType>();
            THROW_IF_NULL_ALLOC(ptr);
            ptr->wchars.assign(wchars.begin(), wchars.end());
            return ptr;
        }
        else if constexpr (NonWrappedStruct<Decayed>)
        {
            Decayed wcharT {};
            wcharT.wchars.assign(wchars.begin(), wchars.end());
            return wcharT;
        }
        else
        {
            static_assert(always_false<FlatbufferType>::value, "CreateWStringT: Unsupported FlatbufferType (must be unique_ptr or struct)");
        }
    }

    template <typename SrcContainer, typename TargetContainer, typename ConvertFunc>
    TargetContainer TransformContainer(const SrcContainer& src_container, ConvertFunc&& conversion_func)
    {
        TargetContainer target_container;
        target_container.reserve(src_container.size());
        for (const auto& value : src_container)
        {
            target_container.emplace_back(conversion_func(value));
        }

        return target_container;
    }

    template <typename SrcContainer, typename ArrayContainer, typename ConvertFunc>
    ArrayContainer TransformToStdArray(const SrcContainer& src_container, ConvertFunc&& conversion_func)
    {
        ArrayContainer array_container {};
        size_t N = std::min(array_container.size(), src_container.size());
        for (size_t i = 0; i < N; ++i)
        {
            array_container[i] = conversion_func(src_container[i]);
        }

        return array_container;
    }

    template <typename FlatbufferType, typename DevType>
    inline std::decay_t<DevType> ConvertToDevType(const FlatbufferType& flatbuffer_type)
    {
        using DecayedDev = std::decay_t<DevType>;
        using DecayedFlatBuffer = std::decay_t<FlatbufferType>;

        if constexpr (AreBothTheSame<DecayedFlatBuffer, DecayedDev>)
        {
            return flatbuffer_type;
        }
        else if constexpr (AreBothArithmeticTypes<DecayedFlatBuffer, DecayedDev>)
        {
            return static_cast<DecayedDev>(flatbuffer_type);
        }
        else if constexpr (AreBothNonWrappedStructs<DecayedFlatBuffer, DecayedDev>)
        {
            DecayedDev dev_type {};
            ConvertStruct<ConversionType::ToDevType, DecayedFlatBuffer, DecayedDev>(flatbuffer_type, dev_type);
            return dev_type;
        }
        else if constexpr (AreBothEnums<DecayedFlatBuffer, DecayedDev>)
        {
            return static_cast<DecayedDev>(flatbuffer_type);
        }
        else if constexpr (AreBothTheSame<DecayedDev, std::wstring>)
        {
            return ConvertToStdWString(flatbuffer_type);
        }
        else if constexpr (AreBothUniquePtrs<DecayedFlatBuffer, DecayedDev>)
        {
            return ConvertToUniquePtr<ConversionType::ToDevType, DecayedFlatBuffer, DecayedDev>(flatbuffer_type);
        }
        else if constexpr (IsOptionalAndUniquePtr<DecayedFlatBuffer, DecayedDev>)
        {
            return ConvertToUniquePtr<ConversionType::ToDevType, DecayedFlatBuffer, DecayedDev>(flatbuffer_type);
        }
        else if constexpr (IsUniquePtrAndNonWrappedStruct<DecayedFlatBuffer, DecayedDev>)
        {
            if (!flatbuffer_type)
            {
                return {};
            }

            using InnerFlatbufferType = unique_ptr_inner_type_t<DecayedFlatBuffer>;
            return ConvertToDevType<InnerFlatbufferType, DecayedDev>(*flatbuffer_type);
        }
        else if constexpr (AreBothVectors<DecayedFlatBuffer, DecayedDev>)
        {
            using InnerDevType = vector_inner_type_t<DecayedDev>;
            using InnerFlatbufferType = vector_inner_type_t<DecayedFlatBuffer>;

            return TransformContainer<DecayedFlatBuffer, DecayedDev>(flatbuffer_type, [] (const InnerFlatbufferType& value)
            {
                return ConvertToDevType<InnerFlatbufferType, InnerDevType>(value);
            });
        }
        else if constexpr (IsVectorAndStdArray<DecayedFlatBuffer, DecayedDev>)
        {
            using InnerDevType = std_array_inner_type_t<DecayedDev>;
            using InnerFlatbufferType = vector_inner_type_t<DecayedFlatBuffer>;

            return TransformToStdArray<DecayedFlatBuffer, DecayedDev>(flatbuffer_type, [] (const InnerFlatbufferType& value)
            {
                return ConvertToDevType<InnerFlatbufferType, InnerDevType>(value);
            });
        }
        else
        {
            static_assert(always_false<FlatbufferType, DevType>::value,
                "Flatbuffer type to Dev type conversion not found in function: " __FUNCSIG__);
        }
    }

    template <typename DevType, typename FlatbufferType>
    inline std::decay_t<FlatbufferType> ConvertToFlatbuffer(const DevType& dev_type)
    {
        using DecayedDev = std::decay_t<DevType>;
        using DecayedFlatBuffer = std::decay_t<FlatbufferType>;

        if constexpr (AreBothTheSame<DecayedDev, DecayedFlatBuffer>)
        {
            return dev_type;
        }
        else if constexpr (AreBothArithmeticTypes<DecayedDev, DecayedFlatBuffer>)
        {
            return static_cast<DecayedFlatBuffer>(dev_type);
        }
        else if constexpr (AreBothNonWrappedStructs<DecayedDev, DecayedFlatBuffer>)
        {
            DecayedFlatBuffer ret {};
            ConvertStruct<ConversionType::ToFlatbuffer, DecayedDev, DecayedFlatBuffer>(dev_type, ret);
            return ret;
        }
        else if constexpr (AreBothEnums<DecayedDev, DecayedFlatBuffer>)
        {
            return static_cast<DecayedFlatBuffer>(dev_type);
        }
        else if constexpr (AreBothTheSame<DecayedDev, std::wstring>)
        {
            return CreateWStringT<DecayedFlatBuffer>(dev_type);
        }
        else if constexpr (AreBothUniquePtrs<DecayedDev, DecayedFlatBuffer>)
        {
            return ConvertToUniquePtr<ConversionType::ToFlatbuffer, DecayedDev, DecayedFlatBuffer>(dev_type);
        }
        else if constexpr (IsRawPtrAndUniquePtr<DecayedDev, DecayedFlatBuffer>)
        {
            return ConvertToUniquePtr<ConversionType::ToFlatbuffer, DecayedDev, DecayedFlatBuffer>(dev_type);
        }
        else if constexpr (IsRawPtrAndNonWrappedStruct<DecayedDev>)
        {
            return ConvertToUniquePtr<ConversionType::ToFlatbuffer, DecayedDev, DecayedFlatBuffer>(dev_type);
        }
        else if constexpr (IsRawPtrAndNotNonWrappedStruct<DecayedDev>)
        {
            return ConvertToOptional<ConversionType::ToFlatbuffer, DecayedDev, DecayedFlatBuffer>(dev_type);
        }
        else if constexpr (IsOptionalAndUniquePtr<DecayedDev, DecayedFlatBuffer>)
        {
            return ConvertToOptional<ConversionType::ToFlatbuffer, DecayedDev, DecayedFlatBuffer>(dev_type);
        }
        else if constexpr (IsUniquePtrAndNonWrappedStruct<DecayedDev, DecayedFlatBuffer>)
        {
            return ConvertToUniquePtr<ConversionType::ToFlatbuffer, DecayedDev, DecayedFlatBuffer>(dev_type);
        }
        else if constexpr (AreBothVectors<DecayedDev, DecayedFlatBuffer>)
        {
            using InnerDevType = vector_inner_type_t<DecayedDev>;
            using InnerFlatbufferType = vector_inner_type_t<DecayedFlatBuffer>;
            
            return TransformContainer<DecayedDev, DecayedFlatBuffer>(dev_type, [] (const InnerDevType& value)
            {
                return ConvertToFlatbuffer<InnerDevType, InnerFlatbufferType>(value);
            });
        }
        else if constexpr (IsVectorAndStdArray<DecayedDev, DecayedFlatBuffer>)
        {
            using InnerDevType = std_array_inner_type_t<DecayedDev>;
            using InnerFlatbufferType = vector_inner_type_t<DecayedFlatBuffer>;

            return TransformContainer<DecayedDev, DecayedFlatBuffer>(dev_type, [] (const InnerDevType& value)
            {
                return ConvertToFlatbuffer<InnerDevType, InnerFlatbufferType>(value);
            });
        }
        else
        {
            static_assert(always_false<DevType, FlatbufferType>::value,
               "Dev type to Flatbuffer type conversion not found in function: " __FUNCSIG__);
        }
    }

    template <ConversionType ConversionT, NonWrappedStruct Src, NonWrappedStruct Target>
    inline void ConvertStruct(const Src& src, Target& target)
    {
        using DecayedSrc = std::decay_t<decltype(src)>;
        using DecayedTarget = std::decay_t<decltype(target)>;

        constexpr size_t N = std::tuple_size_v<decltype(StructMetaData<DecayedSrc>::members)>;
        static_assert(N == std::tuple_size_v<decltype(StructMetaData<DecayedTarget>::members)>,
            "Source and Target structs must have the same number of fields!");

        auto for_each_field = [&]<std::size_t... I>(std::index_sequence<I...>)
        {
            (
                (
                    [&]
                    {
                        auto& src_field = src.*(std::get<I>(StructMetaData<DecayedSrc>::members));
                        auto& dst_field = target.*(std::get<I>(StructMetaData<DecayedTarget>::members));
                        using DecayedSrcFieldT = std::decay_t<decltype(src_field)>;
                        using DecayedTargetFieldT = std::decay_t<decltype(dst_field)>;

                        dst_field = ConvertType<ConversionT, DecayedSrcFieldT, DecayedTargetFieldT>(src_field);
                    }()
                ), ...
            );
        };

        for_each_field(std::make_index_sequence<N>{});
    }
}


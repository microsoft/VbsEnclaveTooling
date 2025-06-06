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
namespace VbsEnclaveABI::Shared::Convertors
{
    template <typename T>
    struct StructMetaData;

    // Helpers
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
    struct is_std_optional : std::false_type {};

    template <typename U>
    struct is_std_optional<std::optional<U>> : std::true_type {};

    template <typename T>
    struct optional_inner_type { using type = void; };

    template <typename U>
    struct optional_inner_type<std::optional<U>> { using type = std::decay_t<U>; };

    template<typename T>
    using std_optional_inner_type_t = optional_inner_type<std::decay_t<T>>::type;

    template <typename T>
    constexpr bool is_std_optional_v = is_std_optional<T>::value;

    template <typename T>
    struct is_std_vector : std::false_type {};

    template <typename U, typename Alloc>
    struct is_std_vector<std::vector<U, Alloc>> : std::true_type {};

    template <typename T>
    struct std_vector_inner_type { using type = void; };

    template <typename U, typename Alloc>
    struct std_vector_inner_type<std::vector<U, Alloc>> { using type = std::decay_t<U>; };

    template<typename T>
    using std_vector_inner_type_t = typename std_vector_inner_type<std::decay_t<T>>::type;

    template <typename T>
    constexpr bool is_std_vector_v = is_std_vector<T>::value;

    template <typename T>
    struct is_std_array : std::false_type {};

    template <typename U, std::size_t N>
    struct is_std_array<std::array<U, N>> : std::true_type {};

    template <typename T>
    struct std_array_inner_type { using type = void; };

    template <typename U, std::size_t N>
    struct std_array_inner_type<std::array<U, N>> { using type = std::decay_t<U>; };

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
    constexpr bool is_std_array_v = is_std_array<T>::value;

    template <typename T>
    using remove_pointer_t = typename std::remove_pointer<T>::type;

    template <typename T>
    constexpr bool is_plain_struct_v =
        std::is_class_v<std::decay_t<T>> &&         // Must be a class or struct
        !is_unique_ptr_v<std::decay_t<T>> &&   // Must not be unique ptr
        !is_std_optional_v<std::decay_t<T>> && // Must not be optional
        !is_container_type<std::decay_t<T>>::value; // Must not be wstring, string, vector or array

    template<typename...> struct always_false : std::false_type {};

    enum class ConversionType : std::uint32_t
    {
        ToDevType,
        ToFlatbuffer
    };

    // Runtime "splitter"
    template<ConversionType conversionT, typename From, typename To>
    std::decay_t<To> ConvertWithType(const From& from)
    {
        using DecayedFrom = std::decay_t<From>;
        using DecayedTo = std::decay_t<To>;

        if constexpr (conversionT == ConversionType::ToDevType)
        {
            return ConvertToDevType<DecayedFrom, DecayedTo>(from);
        }
        else
        {
            return ConvertToFlatbuffer<DecayedFrom, DecayedTo>(from);
        }
    }

    //template <typename FromType, typename ToType>
    //inline std::enable_if_t<is_unique_ptr_v<FromType> && is_plain_struct_v<ToType>, std::decay_t<ToType>>
    //ConvertFromUniquePtrToStruct(const FromType& from_type)
    //{
    //    if (!from_type)
    //    {
    //        return {};
    //    }

    //    using FromInnerType = unique_ptr_inner_type_t<FromType>;
    //    ToType to_type{};
    //    ConvertStruct<FromInnerType, ToType>(*return_ptr, to_type);
    //    return to_type;
    //}

    template <ConversionType conversionT, typename FromType, typename ToType>
    inline std::enable_if_t<is_unique_ptr_v<FromType>, std::decay_t<ToType>>
        ConvertToUniquePtr(const FromType& from_type)
    {
        if (!from_type)
        {
            return nullptr;
        }

        using FromInnerType = unique_ptr_inner_type_t<FromType>;
        using ToInnerType = unique_ptr_inner_type_t<ToType>;

        auto return_ptr = std::make_unique<ToInnerType>();
        THROW_IF_NULL_ALLOC(return_ptr.get());
        *return_ptr = ConvertWithType<conversionT, FromInnerType, ToInnerType>(*from_type);

        return return_ptr;
    }

    template <ConversionType conversionT, typename FromType, typename ToType>
    inline std::enable_if_t<std::is_pointer_v<FromType>, std::decay_t<ToType>>
        ConvertToUniquePtr(const FromType& from_type)
    {
        if (!from_type)
        {
            return nullptr;
        }

        using FromInnerType = std::remove_pointer_t<std::decay_t<FromType>>;
        using ToInnerType = unique_ptr_inner_type_t<ToType>;
        auto return_ptr = std::make_unique<ToInnerType>();
        THROW_IF_NULL_ALLOC(return_ptr.get());
        *return_ptr = ConvertWithType<conversionT, FromInnerType, ToInnerType>(*from_type);

        return return_ptr;
    }

    template <ConversionType conversionT, typename FromType, typename ToType>
    inline std::enable_if_t<is_plain_struct_v<FromType>, std::decay_t<ToType>>
        ConvertToUniquePtr(const FromType& from_type)
    {
        using DecayedFrom = std::decay_t<FromType>;
        using ToInnerType = unique_ptr_inner_type_t<ToType>;
        auto return_ptr = std::make_unique<ToInnerType>();
        THROW_IF_NULL_ALLOC(return_ptr.get());
        *return_ptr = ConvertWithType<conversionT, DecayedFrom, ToInnerType>(from_type);
        return return_ptr;
    }

    template <ConversionType conversionT, typename FromType, typename ToType>
    inline std::enable_if_t<is_std_optional_v<FromType>, std::decay_t<ToType>>
        ConvertToUniquePtr(const FromType& from_type)
    {
        if (!from_type.has_value())
        {
            return {};
        }

        using FromInnerType = optional_inner_type<FromType>::type;
        using ToInnerType = unique_ptr_inner_type_t<ToType>;
        auto return_ptr = std::make_unique<ToInnerType>();
        THROW_IF_NULL_ALLOC(return_ptr.get());
        *return_ptr = ConvertWithType<conversionT, FromInnerType, ToInnerType>(from_type.value());
        return return_ptr;
    }

    template <ConversionType conversionT, typename FromType, typename ToType>
    inline std::enable_if_t<is_unique_ptr_v<FromType>&& is_std_optional_v<ToType>, std::decay_t<ToType>>
        ConvertToOptional(const FromType& from_type)
    {
        if (!from_type)
        {
            return {};
        }

        using FromInnerType = unique_ptr_inner_type_t<FromType>;
        using ToInnerType = std_optional_inner_type_t<ToType>;

        return ConvertWithType<conversionT, FromInnerType, ToInnerType>(*from_type);
    }

    template <ConversionType conversionT, typename FromType, typename ToType>
    inline std::enable_if_t<std::is_pointer_v<FromType>&& is_std_optional_v<ToType>, std::decay_t<ToType>>
        ConvertToOptional(const FromType& from_type)
    {
        if (!from_type)
        {
            return {};
        }

        using FromInnerType = std::remove_pointer_t<std::decay_t<FromType>>;
        using ToInnerType = std_optional_inner_type_t<ToType>;

        return ConvertWithType<conversionT, FromInnerType, ToInnerType>(*from_type);
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

    template<typename FlatbufferType>
    inline std::enable_if_t<is_unique_ptr_v<FlatbufferType>, FlatbufferType>
        CreateWStringT(const std::wstring& wchars)
    {
        using FromInnerType = unique_ptr_inner_type_t<FlatbufferType>;
        auto wchar_ptr = std::make_unique<FromInnerType>();
        THROW_IF_NULL_ALLOC(wchar_ptr);
        wchar_ptr->wchars.assign(wchars.begin(), wchars.end());
        return wchar_ptr;
    }

    template<typename FlatbufferType>
    inline std::enable_if_t<is_plain_struct_v<FlatbufferType>, FlatbufferType>
        CreateWStringT(const std::wstring& wchars)
    {
        FlatbufferType wcharT {};
        wcharT.wchars.assign(wchars.begin(), wchars.end());
        return wcharT;
    }

    template <typename FlatbufferType, typename DevType>
    inline std::decay_t<DevType> ConvertToDevType(const FlatbufferType& flatbuffer_type)
    {
        using DecayedDev = std::decay_t<DevType>;
        using DecayedFlatBuffer = std::decay_t<FlatbufferType>;

        if constexpr (std::is_same_v<DecayedDev, DecayedFlatBuffer>)
        {
            return flatbuffer_type;
        }
        else if constexpr (std::is_arithmetic_v<DecayedFlatBuffer> && std::is_arithmetic_v<DecayedDev>)
        {
            return static_cast<DecayedDev>(flatbuffer_type);
        }
        else if constexpr (is_plain_struct_v<DecayedDev> && is_plain_struct_v<DecayedFlatBuffer>)
        {
            DecayedDev dev_type {};
            ConvertStruct<ConversionType::ToDevType, DecayedFlatBuffer, DecayedDev>(flatbuffer_type, dev_type);
            return dev_type;
        }
        else if constexpr (std::is_enum_v<DecayedFlatBuffer> && std::is_enum_v<DecayedDev>)
        {
            return static_cast<DecayedDev>(flatbuffer_type);
        }
        else if constexpr (std::is_same_v<DecayedDev, std::string>)
        {
            return std::string(flatbuffer_type);
        }
        else if constexpr (std::is_same_v<DecayedDev, std::wstring>)
        {
            return ConvertToStdWString(flatbuffer_type);
        }
        else if constexpr (is_unique_ptr_v<DecayedFlatBuffer> && is_unique_ptr_v<DecayedDev>)
        {
            return ConvertToUniquePtr<ConversionType::ToDevType, DecayedFlatBuffer, DecayedDev>(flatbuffer_type);
        }
        // Handle case where struct field in flatbuffer is std::optional but dev type is unique_ptr struct value
        else if constexpr (is_std_optional_v<DecayedFlatBuffer> && is_unique_ptr_v<DecayedDev>)
        {
            return ConvertToUniquePtr<ConversionType::ToDevType, DecayedFlatBuffer, DecayedDev>(flatbuffer_type);
        }
        // Handle case where struct field in flatbuffer is unique_ptr but dev type is normal struct value
        else if constexpr (is_unique_ptr_v<DecayedFlatBuffer> && is_plain_struct_v<DecayedDev>)
        {
            DecayedDev dev_type {};

            if (!flatbuffer_type)
            {
                return dev_type;
            }

            using FromInnerType = unique_ptr_inner_type_t<DecayedFlatBuffer>;
            ConvertStruct<ConversionType::ToDevType, FromInnerType, DecayedDev>(*flatbuffer_type, dev_type);
            return dev_type;
        }
        else if constexpr (is_std_vector_v<DecayedFlatBuffer> && is_std_vector_v<DecayedDev>)
        {
            using InnerDevType = std_vector_inner_type_t<DecayedDev>;
            using InnerFlatbufferType = std_vector_inner_type_t<DecayedFlatBuffer>;
            DecayedDev dev_type {};
            dev_type.reserve(flatbuffer_type.size());

            for (auto& value : flatbuffer_type)
            {
                dev_type.emplace_back(ConvertToDevType<InnerFlatbufferType, InnerDevType>(value));
            }

            return dev_type;
        }
        else if constexpr (is_std_vector_v<DecayedFlatBuffer> && is_std_array_v<DecayedDev>)
        {
            using InnerDevType = std_array_inner_type_t<DecayedDev>;
            using InnerFlatbufferType = std_vector_inner_type_t<DecayedFlatBuffer>;
            DecayedDev dev_type {};

            for (size_t i = 0; i < std::min(dev_type.size(), flatbuffer_type.size()); i++)
            {
                dev_type[i] = ConvertToDevType<InnerFlatbufferType, InnerDevType>(flatbuffer_type[i]);
            }

            return dev_type;
        }
        else
        {
            static_assert(always_false<FlatbufferType, DevType>::value,
                "Flatbuffer type to Dev type conversion not found in function:" __FUNCSIG__);
        }
    }

    template <typename DevType, typename FlatbufferType>
    inline std::decay_t<FlatbufferType> ConvertToFlatbuffer(const DevType& dev_type)
    {
        using DecayedDev = std::decay_t<DevType>;
        using DecayedFlatBuffer = std::decay_t<FlatbufferType>;

        if constexpr (std::is_same_v<DecayedDev, DecayedFlatBuffer>)
        {
            return dev_type;
        }
        else if constexpr (std::is_arithmetic_v<DecayedDev> && std::is_arithmetic_v<DecayedFlatBuffer>)
        {
            return static_cast<DecayedFlatBuffer>(dev_type);
        }
        else if constexpr (is_plain_struct_v<DecayedDev> && is_plain_struct_v<DecayedFlatBuffer>)
        {
            DecayedFlatBuffer ret {};
            ConvertStruct<ConversionType::ToFlatbuffer, DecayedDev, DecayedFlatBuffer>(dev_type, ret);
            return ret;
        }
        else if constexpr (std::is_enum_v<DecayedDev> && std::is_enum_v<DecayedFlatBuffer>)
        {
            return static_cast<DecayedFlatBuffer>(dev_type);
        }
        else if constexpr (std::is_same_v<DecayedDev, std::string>)
        {
            return std::string(dev_type);
        }
        else if constexpr (std::is_same_v<DecayedDev, std::wstring>)
        {
            return CreateWStringT<DecayedFlatBuffer>(dev_type);
        }
        else if constexpr (is_unique_ptr_v<DecayedDev> && is_unique_ptr_v<DecayedFlatBuffer>)
        {
            return ConvertToUniquePtr<ConversionType::ToFlatbuffer, DecayedDev, DecayedFlatBuffer>(dev_type);
        }
        else if constexpr (std::is_pointer_v<DecayedDev> && is_unique_ptr_v<DecayedFlatBuffer>)
        {
            return ConvertToUniquePtr<ConversionType::ToFlatbuffer, DecayedDev, DecayedFlatBuffer>(dev_type);
        }
        else if constexpr (std::is_pointer_v<DecayedDev> && !is_plain_struct_v<remove_pointer_t<DecayedDev>>)
        {
            return ConvertToOptional<ConversionType::ToFlatbuffer, DecayedDev, DecayedFlatBuffer>(dev_type);
        }
        else if constexpr (std::is_pointer_v<DecayedDev> && is_plain_struct_v<remove_pointer_t<DecayedDev>>)
        {
            return ConvertToUniquePtr<ConversionType::ToFlatbuffer, DecayedDev, DecayedFlatBuffer>(dev_type);
        }
        // Handle case where struct field in flatbuffer is std::optional but dev type is unique_ptr struct value
        else if constexpr (is_std_optional_v<DecayedFlatBuffer> && is_unique_ptr_v<DecayedDev>)
        {
            return ConvertToOptional<ConversionType::ToFlatbuffer, DecayedDev, DecayedFlatBuffer>(dev_type);
        }
        // Handle case where struct field in flatbuffer is unique_ptr but dev type is normal struct value
        else if constexpr (is_unique_ptr_v<DecayedFlatBuffer> && is_plain_struct_v<DecayedDev>)
        {
            return ConvertToUniquePtr<ConversionType::ToFlatbuffer, DecayedDev, DecayedFlatBuffer>(dev_type);
        }
        else if constexpr (is_std_vector_v<DecayedDev> && is_std_vector_v<DecayedFlatBuffer>)
        {
            using InnerDevType = std_vector_inner_type_t<DecayedDev>;
            using InnerFlatbufferType = std_vector_inner_type_t<DecayedFlatBuffer>;
            DecayedFlatBuffer flatbuffer {};
            flatbuffer.reserve(dev_type.size());

            for (auto& value : dev_type)
            {
                flatbuffer.emplace_back(ConvertToFlatbuffer<InnerDevType, InnerFlatbufferType>(value));
            }

            return flatbuffer;
        }
        else if constexpr (is_std_array_v<DecayedDev> && is_std_vector_v<DecayedFlatBuffer>)
        {
            using InnerDevType = std_array_inner_type_t<DecayedDev>;
            using InnerFlatbufferType = std_vector_inner_type_t<DecayedFlatBuffer>;
            DecayedFlatBuffer flatbuffer {};
            flatbuffer.reserve(dev_type.size());

            for (size_t i = 0; i < dev_type.size(); i++)
            {
                flatbuffer.emplace_back(ConvertToFlatbuffer<InnerDevType, InnerFlatbufferType>(dev_type[i]));
            }

            return flatbuffer;
        }
        else
        {
            static_assert(always_false<DevType, FlatbufferType>::value,
               "Dev type to Flatbuffer type conversion not found in function:" __FUNCSIG__);
        }
    }

    template <ConversionType conversionT, typename From, typename To, size_t... I>
    inline std::enable_if_t<is_plain_struct_v<From>&& is_plain_struct_v<To>, void>
    ConvertStructImpl(const From& from, To& to, std::index_sequence<I...>)
    {
        (
            (
            [&]
            {
                auto& src_field = from.*(std::get<I>(StructMetaData<From>::members));
                auto& dst_field = to.*(std::get<I>(StructMetaData<To>::members));
                using SrcT = std::decay_t<decltype(src_field)>;
                using DstT = std::decay_t<decltype(dst_field)>;

                if constexpr (is_plain_struct_v<SrcT> && is_plain_struct_v<DstT>)
                {
                    ConvertStruct<conversionT, SrcT, DstT>(src_field, dst_field);
                }
                else
                {
                    dst_field = ConvertWithType<conversionT, SrcT, DstT>(src_field);
                }
            }()
            ), ...
        );
    }

    template <ConversionType conversionT, typename From, typename To>
    inline std::enable_if_t<is_plain_struct_v<From> && is_plain_struct_v<To>, void>
    ConvertStruct(const From& from, To& to)
    {
        using SrcT = std::decay_t<decltype(from)>;
        using DstT = std::decay_t<decltype(to)>;

        constexpr size_t N = StructMetaData<SrcT>::count;
        static_assert(N == StructMetaData<DstT>::count, "Structs must have the same number of fields!");
        ConvertStructImpl<conversionT, SrcT, DstT>(from, to, std::make_index_sequence<N>{});
    }

    template <ConversionType conversionT, typename From, typename To>
    inline std::enable_if_t<!is_plain_struct_v<From> || !is_plain_struct_v<To>, void>
    ConvertStruct(const From& from, To& to)
    {
    }
}


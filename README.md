> 版权归作者所有，如有转发，请注明文章出处：<https://cyrus-studio.github.io/blog/>

# **DEF CON**



DEF CON 是全球最大的计算机安全会议之一（极客的奥斯卡），自1993年6月起，每年在美国内华达州的拉斯维加斯举办。



官网：[https://media.defcon.org/](https://media.defcon.org/)，DEF CON 黑客大会官方的媒体存档站点，提供历年 DEF CON 大会的公开演讲、幻灯片、视频、音频、代码示例和其他相关资源的免费下载。



在 DEF CON 25（2017 年）上，Check Point 的安全研究员 Slava Makkaveev 和 Avi Bashan 发表了题为《Unboxing Android: Everything You Wanted to Know About Android Packers》的演讲，深入探讨了 Android 应用程序中的加壳技术及其安全影响。



报告文件地址：

[https://media.defcon.org/DEF%20CON%2025/DEF%20CON%2025%20presentations/DEF%20CON%2025%20-%20Slava-Makkaveev-and-Avi-Bashan-Unboxing-Android.pdf](https://media.defcon.org/DEF%20CON%2025/DEF%20CON%2025%20presentations/DEF%20CON%2025%20-%20Slava-Makkaveev-and-Avi-Bashan-Unboxing-Android.pdf)



对于国内加壳厂商也有分析



![word/media/image1.png](https://gitee.com/cyrus-studio/images/raw/master/85777d44ae42a2c7de18295d01712c01.png)


DEF 的安全研究员选择的两个脱壳点：art::OpenAndReadMagic 和 DexFile::DexFile



![word/media/image2.png](https://gitee.com/cyrus-studio/images/raw/master/26614f34fc11c05f376afdac726283da.png)


# **Unboxing Android**



在 DEF CON 25 (2017) 上，Avi Bashan 和 Slava Makkaveev 提出过一种非常实用的 Android 加壳脱壳技术：



通过修改 DexFile::DexFile() 构造函数和 OpenAndReadMagic() 方法，可以在应用运行时，拦截 DEX 文件加载过程，从而拿到已经解密后的内存数据，完成脱壳。



## **1. DexFile::DexFile 构造函数**



可以看到 DexFile::DexFile() 的构造函数参数里包含了：

- const uint8_t* base —— DEX 在内存中的起始地址

- size_t size —— DEX 的内存大小

```
DexFile::DexFile(const uint8_t* base,
                 size_t size,
                 const uint8_t* data_begin,
                 size_t data_size,
                 const std::string& location,
                 uint32_t location_checksum,
                 const OatDexFile* oat_dex_file,
                 std::unique_ptr<DexFileContainer> container,
                 bool is_compact_dex)
    : begin_(base),
      size_(size),
      data_begin_(data_begin),
      data_size_(data_size),
      location_(location),
      location_checksum_(location_checksum),
      header_(reinterpret_cast<const Header*>(base)),
      string_ids_(reinterpret_cast<const StringId*>(base + header_->string_ids_off_)),
      type_ids_(reinterpret_cast<const TypeId*>(base + header_->type_ids_off_)),
      field_ids_(reinterpret_cast<const FieldId*>(base + header_->field_ids_off_)),
      method_ids_(reinterpret_cast<const MethodId*>(base + header_->method_ids_off_)),
      proto_ids_(reinterpret_cast<const ProtoId*>(base + header_->proto_ids_off_)),
      class_defs_(reinterpret_cast<const ClassDef*>(base + header_->class_defs_off_)),
      method_handles_(nullptr),
      num_method_handles_(0),
      call_site_ids_(nullptr),
      num_call_site_ids_(0),
      hiddenapi_class_data_(nullptr),
      oat_dex_file_(oat_dex_file),
      container_(std::move(container)),
      is_compact_dex_(is_compact_dex),
      hiddenapi_domain_(hiddenapi::Domain::kApplication) {
  CHECK(begin_ != nullptr) << GetLocation();
  CHECK_GT(size_, 0U) << GetLocation();
  // Check base (=header) alignment.
  // Must be 4-byte aligned to avoid undefined behavior when accessing
  // any of the sections via a pointer.
  CHECK_ALIGNED(begin_, alignof(Header));

  InitializeSectionsFromMapList();
}
```
[https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/libdexfile/dex/dex_file.cc;l=96](https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/libdexfile/dex/dex_file.cc;l=96)





![word/media/image3.png](https://gitee.com/cyrus-studio/images/raw/master/19c80e4b1d1d1e8ba82186864d060e97.png)


插入脱壳代码示例

```
// 打印当前 DEX 文件的位置
LOG(WARNING) << "Dex File: Filename: " << location;

// 判断这个 DEX 是不是从 APP 自身私有目录 加载的。
// 因为系统自己的 framework、boot.oat 里的 DEX 都不是加壳 DEX，只想 dump 应用自己的 DEX。
if (location.find("/data/data/") != std::string::npos) {
    LOG(WARNING) << "Dex File: OAT file unpacking launched";

    // 创建一个新的文件，比如 /data/data/包名/xxx.dex__unpacked_oat。
    std::ofstream dst(location + "__unpacked_oat", std::ios::binary);
    // 把内存里的 DEX 数据完整写入磁盘。
    dst.write(reinterpret_cast<const char*>(base), size);
    // 保存文件，完成脱壳。
    dst.close();
} else {
    LOG(WARNING) << "Dex File: OAT file unpacking not launched";
}
```


## **2. DexFile::OpenAndReadMagic()**



这是辅助检查 DEX 文件头的函数。

```
File OpenAndReadMagic(const char* filename, uint32_t* magic, std::string* error_msg) {
  CHECK(magic != nullptr);
  File fd(filename, O_RDONLY, /* check_usage= */ false);
  if (fd.Fd() == -1) {
    *error_msg = StringPrintf("Unable to open '%s' : %s", filename, strerror(errno));
    return File();
  }
  if (!ReadMagicAndReset(fd.Fd(), magic, error_msg)) {
    StringPrintf("Error in reading magic from file %s: %s", filename, error_msg->c_str());
    return File();
  }
  return fd;
}
```
[https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/libartbase/base/file_magic.cc;l=32](https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/libartbase/base/file_magic.cc;l=32)





![word/media/image4.png](https://gitee.com/cyrus-studio/images/raw/master/c4f07ae80a53cb21b2ed7bb7b2ee3f58.png)


插入脱壳代码示例

```
struct stat st;  // 用于获取文件大小等信息

// 打印当前正在处理的文件路径，便于调试和观察加载的 DEX 来源
LOG(WARNING) << "File_magic: Filename: " << filename;

// 只处理 /data/data 路径下的文件（即应用私有目录中的 dex 文件）
// 这样可以避免处理系统 DEX，提高效率和准确性
if (strstr(filename, "/data/data") != NULL) {
  LOG(WARNING) << "File_magic: DEX file unpacking launched";

  // 构造输出文件路径，加上 "__unpacked_dex" 后缀
  char* fn_out = new char[PATH_MAX];
  strcpy(fn_out, filename);
  strcat(fn_out, "__unpacked_dex");

  // 创建输出文件，设置权限：用户可读写、用户组可读、其他人可读
  int fd_out = open(fn_out, O_WRONLY | O_CREAT | O_EXCL,
                    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

  // 如果获取原始 dex 文件信息成功（用于获取文件大小）
  if (!fstat(fd.get(), &st)) {
    // 使用 mmap 将整个 dex 文件映射到内存中
    char* addr = (char*)mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd.get(), 0);

    // 将内存中的内容写入到新文件，完成磁盘级别的 dex dump
    int ret = write(fd_out, addr, st.st_size);

    // 可选防优化代码（保证 ret 被使用，防止编译器优化）
    ret += 1;

    // 解除映射，释放内存
    munmap(addr, st.st_size);
  }

  // 关闭输出文件，清理路径内存
  close(fd_out);
  delete[] fn_out;

} else {
  // 如果不是应用私有路径下的文件，跳过处理
  LOG(WARNING) << "File_magic: DEX file unpacking not launched";
}
```


# **ART 下脱壳原理**



ART 下常见的两个 dex 加载器：InMemoryDexClassLoader 和 DexClassLoader



## **InMemoryDexClassLoader 源码分析**



InMemoryDexClassLoader 是 Android 8.0（API 级别 26）引入的一个类，用于动态加载内存中的 Dex。



调用示例：

```
// 假设 dexBytes 是你的 DEX 文件内容（可以通过解密获得）
ByteBuffer buffer = ByteBuffer.wrap(dexBytes);

// 创建 InMemoryDexClassLoader
ClassLoader loader = new InMemoryDexClassLoader(buffer, ClassLoader.getSystemClassLoader());

// 通过反射加载类并调用方法
Class<?> clazz = loader.loadClass("com.example.MyHiddenClass");
Method m = clazz.getDeclaredMethod("secretMethod");
m.invoke(null);
```


InMemoryDexClassLoader 支持加载 内存中 一个或多个 Dex。源码如下：



![word/media/image5.png](https://gitee.com/cyrus-studio/images/raw/master/882c2733141420f573b56a73a7166520.png)
[https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:libcore/dalvik/src/main/java/dalvik/system/InMemoryDexClassLoader.java](https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:libcore/dalvik/src/main/java/dalvik/system/InMemoryDexClassLoader.java)



### **openInMemoryDexFilesNative**



Dex 加载过程如下，最终调用到 native 方法 openInMemoryDexFilesNative

```
 InMemoryDexClassLoader(ByteBuffer[] dexBuffers, String librarySearchPath, ClassLoader parent)
 └── BaseDexClassLoader(ByteBuffer[] dexFiles, String librarySearchPath, ClassLoader parent)
      └── DexPathList.initByteBufferDexPath(ByteBuffer[] dexFiles)
           └── DexFile(ByteBuffer[] bufs, ClassLoader loader, DexPathList.Element[] elements)
                └── DexFile.openInMemoryDexFiles(ByteBuffer[] bufs, ClassLoader loader, DexPathList.Element[] elements)
                     └── DexFile.openInMemoryDexFilesNative(ByteBuffer[] bufs, byte[][] arrays, int[] starts, int[] ends, ClassLoader loader, DexPathList.Element[] elements)
                         └── DexFile_openInMemoryDexFilesNative(JNIEnv* env, jclass, jobjectArray buffers, jobjectArray arrays, jintArray jstarts, jintArray jends, jobject class_loader, jobjectArray dex_elements)
```
[https://cs.android.com/android/platform/superproject/main/+/main:libcore/dalvik/src/main/java/dalvik/system/DexFile.java;l=134](https://cs.android.com/android/platform/superproject/main/+/main:libcore/dalvik/src/main/java/dalvik/system/DexFile.java;l=134)



DexFile_openInMemoryDexFilesNative 中 调用 OpenDexFilesFromOat 方法 加载 Dex ：

```
static jobject DexFile_openInMemoryDexFilesNative(JNIEnv* env,
                                                  jclass,
                                                  jobjectArray buffers,
                                                  jobjectArray arrays,
                                                  jintArray jstarts,
                                                  jintArray jends,
                                                  jobject class_loader,
                                                  jobjectArray dex_elements) {
  jsize buffers_length = env->GetArrayLength(buffers);
  CHECK_EQ(buffers_length, env->GetArrayLength(arrays));
  CHECK_EQ(buffers_length, env->GetArrayLength(jstarts));
  CHECK_EQ(buffers_length, env->GetArrayLength(jends));

  ScopedIntArrayAccessor starts(env, jstarts);
  ScopedIntArrayAccessor ends(env, jends);

  // Allocate memory for dex files and copy data from ByteBuffers.
  std::vector<MemMap> dex_mem_maps;
  dex_mem_maps.reserve(buffers_length);
  for (jsize i = 0; i < buffers_length; ++i) {
    jobject buffer = env->GetObjectArrayElement(buffers, i);
    jbyteArray array = reinterpret_cast<jbyteArray>(env->GetObjectArrayElement(arrays, i));
    jint start = starts.Get(i);
    jint end = ends.Get(i);

    MemMap dex_data = AllocateDexMemoryMap(env, start, end);
    if (!dex_data.IsValid()) {
      DCHECK(Thread::Current()->IsExceptionPending());
      return nullptr;
    }

    if (array == nullptr) {
      // Direct ByteBuffer
      uint8_t* base_address = reinterpret_cast<uint8_t*>(env->GetDirectBufferAddress(buffer));
      if (base_address == nullptr) {
        ScopedObjectAccess soa(env);
        ThrowWrappedIOException("dexFileBuffer not direct");
        return nullptr;
      }
      size_t length = static_cast<size_t>(end - start);
      memcpy(dex_data.Begin(), base_address + start, length);
    } else {
      // ByteBuffer backed by a byte array
      jbyte* destination = reinterpret_cast<jbyte*>(dex_data.Begin());
      env->GetByteArrayRegion(array, start, end - start, destination);
    }

    dex_mem_maps.push_back(std::move(dex_data));
  }

  // Hand MemMaps over to OatFileManager to open the dex files and potentially
  // create a backing OatFile instance from an anonymous vdex.
  std::vector<std::string> error_msgs;
  const OatFile* oat_file = nullptr;
  std::vector<std::unique_ptr<const DexFile>> dex_files =
      Runtime::Current()->GetOatFileManager().OpenDexFilesFromOat(std::move(dex_mem_maps),
                                                                  class_loader,
                                                                  dex_elements,
                                                                  /*out*/ &oat_file,
                                                                  /*out*/ &error_msgs);
  return CreateCookieFromOatFileManagerResult(env, dex_files, oat_file, error_msgs);
}
```
[https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/runtime/native/dalvik_system_DexFile.cc;l=240](https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/runtime/native/dalvik_system_DexFile.cc;l=240)



### **OpenDexFilesFromOat**



OpenDexFilesFromOat 调用 OpenDexFilesFromOat_Impl 加载 Dex

```
std::vector<std::unique_ptr<const DexFile>> OatFileManager::OpenDexFilesFromOat_Impl(
    std::vector<MemMap>&& dex_mem_maps,
    jobject class_loader,
    jobjectArray dex_elements,
    const OatFile** out_oat_file,
    std::vector<std::string>* error_msgs) {
  ScopedTrace trace(__FUNCTION__);
  std::string error_msg;
  DCHECK(error_msgs != nullptr);

  // [1] 提取 Dex Header，用于后续校验 checksum、生成路径等
  const std::vector<const DexFile::Header*> dex_headers = GetDexFileHeaders(dex_mem_maps);

  // [2] 生成临时匿名 dex/vdex 文件路径，获取 checksum 和路径
  uint32_t location_checksum;
  std::string dex_location;
  std::string vdex_path;
  bool has_vdex = OatFileAssistant::AnonymousDexVdexLocation(
      dex_headers, kRuntimeISA, &location_checksum, &dex_location, &vdex_path);

  // [3] 尝试打开 vdex 文件，并检查其中的 dex checksum 是否一致
  std::unique_ptr<VdexFile> vdex_file = nullptr;
  if (has_vdex && OS::FileExists(vdex_path.c_str())) {
    vdex_file = VdexFile::Open(vdex_path, /*writable=*/false, /*low_4gb=*/false,
                               /*unquicken=*/false, &error_msg);
    if (vdex_file == nullptr) {
      LOG(WARNING) << "Failed to open vdex " << vdex_path << ": " << error_msg;
    } else if (!vdex_file->MatchesDexFileChecksums(dex_headers)) {
      LOG(WARNING) << "Dex checksum mismatch: " << vdex_path;
      vdex_file.reset(nullptr);
    }
  }

  // [4] 加载内存中的 dex。若存在 vdex 且校验成功，可跳过结构校验
  std::vector<std::unique_ptr<const DexFile>> dex_files;
  for (size_t i = 0; i < dex_mem_maps.size(); ++i) {
    static constexpr bool kVerifyChecksum = true;
    const ArtDexFileLoader dex_file_loader;
    std::unique_ptr<const DexFile> dex_file(dex_file_loader.Open(
        DexFileLoader::GetMultiDexLocation(i, dex_location.c_str()),
        location_checksum,
        std::move(dex_mem_maps[i]),
        /*verify=*/(vdex_file == nullptr) && Runtime::Current()->IsVerificationEnabled(),
        kVerifyChecksum,
        &error_msg));
    if (dex_file != nullptr) {
      dex::tracking::RegisterDexFile(dex_file.get());  // 注册用于调试追踪
      dex_files.push_back(std::move(dex_file));
    } else {
      error_msgs->push_back("Failed to open dex files from memory: " + error_msg);
    }
  }

  // [5] 若 vdex 不存在、加载失败，或 class_loader 为空，直接返回 dex_files
  if (vdex_file == nullptr || class_loader == nullptr || !error_msgs->empty()) {
    return dex_files;
  }

  // [6] 创建 ClassLoaderContext，确保之后的 oat 加载上下文一致
  std::unique_ptr<ClassLoaderContext> context = ClassLoaderContext::CreateContextForClassLoader(
      class_loader, dex_elements);
  if (context == nullptr) {
    LOG(ERROR) << "Could not create class loader context for " << vdex_path;
    return dex_files;
  }
  DCHECK(context->OpenDexFiles(kRuntimeISA, ""))
      << "Context created from already opened dex files should not attempt to open again";

  // [7] 检查 boot class path checksum 和 class loader context 是否匹配
  if (!vdex_file->MatchesBootClassPathChecksums() ||
      !vdex_file->MatchesClassLoaderContext(*context.get())) {
    return dex_files;
  }

  // [8] 从 vdex 创建 OatFile 实例并注册
  std::unique_ptr<OatFile> oat_file(OatFile::OpenFromVdex(
      MakeNonOwningPointerVector(dex_files),
      std::move(vdex_file),
      dex_location));
  DCHECK(oat_file != nullptr);
  VLOG(class_linker) << "Registering " << oat_file->GetLocation();
  *out_oat_file = RegisterOatFile(std::move(oat_file));

  return dex_files;
}
```
[https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/runtime/oat_file_manager.cc;l=708](https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/runtime/oat_file_manager.cc;l=708)



在 Android 10 之前，InMemoryDexClassLoader 加载的 DEX 文件不会被编译为 OAT 文件，而是直接在解释模式下执行， 这也是它和 DexClassLoader 的区别。



从 Android 10 开始，InMemoryDexClassLoader 加载的 DEX 文件也会走 OAT 流程。



DexFile_openInMemoryDexFilesNative → DexFile::DexFile 调用路径

```
DexFile_openInMemoryDexFilesNative(...)                    
└── AllocateDexMemoryMap(...) 创建 dex_mem_maps
└── Runtime::Current()->GetOatFileManager().OpenDexFilesFromOat(...) 
    └── OatFileManager::OpenDexFilesFromOat(dex_mem_maps, class_loader, dex_elements, out_oat_file, error_msgs)
        └── OatFileManager::OpenDexFilesFromOat_Impl(...)
            └── ArtDexFileLoader::Open(location, location_checksum, map, verify, verify_checksum, error_msg)
                  └── ArtDexFileLoader::OpenCommon(base, size, ...)
                        └── DexFileLoader::OpenCommon(base, size, ...)
                            └── new StandardDexFile(base, location, ...): DexFile(base, location, ...)
                            └── new CompactDexFile(base, location, ...): DexFile(base, location, ...)
```
[https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/runtime/oat_file_manager.cc;l=708](https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/runtime/oat_file_manager.cc;l=708)



### **OpenCommon**



在这些关键 api 当中我们都可以拿到 dex 的起始地址和 size 来进行 dump

```
ArtDexFileLoader::Open(location, location_checksum, map, verify, verify_checksum, error_msg)
  └── ArtDexFileLoader::OpenCommon(base, size, ...)
        └── DexFileLoader::OpenCommon(base, size, ...)
            └── new StandardDexFile(base, location, ...): DexFile(base, location, ...)
            └── new CompactDexFile(base, location, ...): DexFile(base, location, ...)
```
[https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/libdexfile/dex/art_dex_file_loader.cc;l=184](https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/libdexfile/dex/art_dex_file_loader.cc;l=184)

[https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/libdexfile/dex/dex_file_loader.cc;l=316](https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/libdexfile/dex/dex_file_loader.cc;l=316)

[https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/libdexfile/dex/standard_dex_file.h;l=100](https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/libdexfile/dex/standard_dex_file.h;l=100)

[https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/libdexfile/dex/dex_file.cc;l=96](https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/libdexfile/dex/dex_file.cc;l=96)



## **DexClassLoader 源码分析**



DexClassLoader 可以加载任意路径下的 dex，或者 jar、apk、zip 文件（包含classes.dex）。



源码如下：



![word/media/image6.png](https://gitee.com/cyrus-studio/images/raw/master/05532442ff68769ffc74626f16ea0ad9.png)
[https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:libcore/dalvik/src/main/java/dalvik/system/DexClassLoader.java](https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:libcore/dalvik/src/main/java/dalvik/system/DexClassLoader.java)



### **DexFile_openDexFileNative**



DexClassLoader 最终是通过 JNI 调用 DexFile_openDexFileNative 来加载 Dex。



下面是从 Java 到 native 的完整调用路径（以 Android 10 为例）：

```
DexClassLoader(String dexPath, String optimizedDirectory, String librarySearchPath, ClassLoader parent)
   ↓
BaseDexClassLoader(String dexPath, File optimizedDirectory, String librarySearchPath, ClassLoader parent)
   ↓
DexPathList(ClassLoader definingContext, String dexPath, String librarySearchPath, File optimizedDirectory, boolean isTrusted)
   ↓
DexPathList.makeDexElements(...)
   ↓
new DexFile(file, loader, elements)
   ↓
DexFile.openDexFile(fileName, null, 0, loader, elements)
   ↓
DexFile.openDexFileNative(sourceFile, outputFile, flags, loader, elements)
   ↓
DexFile_openDexFileNative(...) （native 层）
```
[https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:libcore/dalvik/src/main/java/dalvik/system/DexFile.java;l=440](https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:libcore/dalvik/src/main/java/dalvik/system/DexFile.java;l=440)



DexFile_openDexFileNative 方法中调用 OpenDexFilesFromOat 方法生成 OAT 文件：

```
static jobject DexFile_openDexFileNative(JNIEnv* env,
                                         jclass,
                                         jstring javaSourceName,
                                         jstring javaOutputName ATTRIBUTE_UNUSED,
                                         jint flags ATTRIBUTE_UNUSED,
                                         jobject class_loader,
                                         jobjectArray dex_elements) {
  ScopedUtfChars sourceName(env, javaSourceName);
  if (sourceName.c_str() == nullptr) {
    return nullptr;
  }

  std::vector<std::string> error_msgs;
  const OatFile* oat_file = nullptr;
  std::vector<std::unique_ptr<const DexFile>> dex_files =
      Runtime::Current()->GetOatFileManager().OpenDexFilesFromOat(sourceName.c_str(),
                                                                  class_loader,
                                                                  dex_elements,
                                                                  /*out*/ &oat_file,
                                                                  /*out*/ &error_msgs);
  return CreateCookieFromOatFileManagerResult(env, dex_files, oat_file, error_msgs);
}
```
[https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/runtime/native/dalvik_system_DexFile.cc](https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/runtime/native/dalvik_system_DexFile.cc)



### **OpenDexFilesFromOat**



和 InMemoryDexClassLoader 不同的是：这里传入的参数不是 MemMap，而是 const char* dex_location。



OpenDexFilesFromOat 方法源码如下：

```
std::vector<std::unique_ptr<const DexFile>> OatFileManager::OpenDexFilesFromOat(
    const char* dex_location,
    jobject class_loader,
    jobjectArray dex_elements,
    const OatFile** out_oat_file,
    std::vector<std::string>* error_msgs) {
  ScopedTrace trace(__FUNCTION__);
  CHECK(dex_location != nullptr);
  CHECK(error_msgs != nullptr);

  // 步骤 1: 确保未持有 mutator_lock，防止阻塞 GC
  Thread* const self = Thread::Current();
  Locks::mutator_lock_->AssertNotHeld(self);
  Runtime* const runtime = Runtime::Current();

  // 步骤 2: 构造 ClassLoaderContext（可能为空）
  std::unique_ptr<ClassLoaderContext> context;
  if (class_loader == nullptr) {
    LOG(WARNING) << "Opening an oat file without a class loader. "
                 << "Are you using the deprecated DexFile APIs?";
    context = nullptr;
  } else {
    context = ClassLoaderContext::CreateContextForClassLoader(class_loader, dex_elements);
  }

  // 步骤 3: 构建 OatFileAssistant，用于操作 oat 和 dex 文件
  OatFileAssistant oat_file_assistant(dex_location,
                                      kRuntimeISA,
                                      !runtime->IsAotCompiler(),
                                      only_use_system_oat_files_);

  // 步骤 4: 获取磁盘上最优的 OAT 文件
  std::unique_ptr<const OatFile> oat_file(oat_file_assistant.GetBestOatFile().release());
  VLOG(oat) << "OatFileAssistant(" << dex_location << ").GetBestOatFile()="
            << reinterpret_cast<uintptr_t>(oat_file.get())
            << " (executable=" << (oat_file != nullptr ? oat_file->IsExecutable() : false) << ")";

  const OatFile* source_oat_file = nullptr;
  CheckCollisionResult check_collision_result = CheckCollisionResult::kPerformedHasCollisions;
  std::string error_msg;

  // 步骤 5: 进行 collision 检查决定是否接受这个 oat 文件
  if ((class_loader != nullptr || dex_elements != nullptr) && oat_file != nullptr) {
    check_collision_result = CheckCollision(oat_file.get(), context.get(), &error_msg);
    bool accept_oat_file = AcceptOatFile(check_collision_result);

    // 检查结果为 false，判断是否启用 fallback 并记录警告信息
    if (!accept_oat_file) {
      if (runtime->IsDexFileFallbackEnabled()) {
        if (!oat_file_assistant.HasOriginalDexFiles()) {
          accept_oat_file = true;
          LOG(WARNING) << "Dex location " << dex_location << " does not seem to include dex file. "
                       << "Allow oat file use. This is potentially dangerous.";
        } else {
          LOG(WARNING) << "Found duplicate classes, falling back to extracting from APK : "
                       << dex_location;
          LOG(WARNING) << "NOTE: This wastes RAM and hurts startup performance.";
        }
      } else {
        if (!oat_file_assistant.HasOriginalDexFiles()) {
          accept_oat_file = true;
        }
        LOG(WARNING) << "Found duplicate classes, dex-file-fallback disabled, will be failing to "
                        " load classes for " << dex_location;
      }

      LOG(WARNING) << error_msg;
    }

    // 步骤 6: 注册 oat 文件到 OatFileManager
    if (accept_oat_file) {
      VLOG(class_linker) << "Registering " << oat_file->GetLocation();
      source_oat_file = RegisterOatFile(std::move(oat_file));
      *out_oat_file = source_oat_file;
    }
  }

  std::vector<std::unique_ptr<const DexFile>> dex_files;

  // 步骤 7: 从 OAT 文件加载 dex 文件（如果成功加载了 oat）
  if (source_oat_file != nullptr) {
    bool added_image_space = false;

    if (source_oat_file->IsExecutable()) {
      ScopedTrace app_image_timing("AppImage:Loading");

      std::unique_ptr<gc::space::ImageSpace> image_space;
      if (ShouldLoadAppImage(check_collision_result,
                             source_oat_file,
                             context.get(),
                             &error_msg)) {
        image_space = oat_file_assistant.OpenImageSpace(source_oat_file);
      }

      if (image_space != nullptr) {
        ScopedObjectAccess soa(self);
        StackHandleScope<1> hs(self);
        Handle<mirror::ClassLoader> h_loader(
            hs.NewHandle(soa.Decode<mirror::ClassLoader>(class_loader)));

        // 步骤 8: 尝试将 image space 添加到堆中
        if (h_loader != nullptr) {
          std::string temp_error_msg;
          {
            ScopedThreadSuspension sts(self, kSuspended);
            gc::ScopedGCCriticalSection gcs(self,
                                            gc::kGcCauseAddRemoveAppImageSpace,
                                            gc::kCollectorTypeAddRemoveAppImageSpace);
            ScopedSuspendAll ssa("Add image space");
            runtime->GetHeap()->AddSpace(image_space.get());
          }
          {
            ScopedTrace trace2(StringPrintf("Adding image space for location %s", dex_location));
            added_image_space = runtime->GetClassLinker()->AddImageSpace(image_space.get(),
                                                                         h_loader,
                                                                         dex_elements,
                                                                         dex_location,
                                                                         &dex_files,
                                                                         &temp_error_msg);
          }
          if (added_image_space) {
            image_space.release();
            for (const auto& dex_file : dex_files) {
              dex::tracking::RegisterDexFile(dex_file.get());
            }
          } else {
            LOG(INFO) << "Failed to add image file " << temp_error_msg;
            dex_files.clear();
            {
              ScopedThreadSuspension sts(self, kSuspended);
              gc::ScopedGCCriticalSection gcs(self,
                                              gc::kGcCauseAddRemoveAppImageSpace,
                                              gc::kCollectorTypeAddRemoveAppImageSpace);
              ScopedSuspendAll ssa("Remove image space");
              runtime->GetHeap()->RemoveSpace(image_space.get());
            }
          }
        }
      }
    }

    // 步骤 9: 如果未添加 image space，则从 oat 中手动加载 dex 文件
    if (!added_image_space) {
      DCHECK(dex_files.empty());
      dex_files = oat_file_assistant.LoadDexFiles(*source_oat_file, dex_location);

      for (const auto& dex_file : dex_files) {
        dex::tracking::RegisterDexFile(dex_file.get());
      }
    }

    // 步骤 10: 检查是否 dex 文件加载失败
    if (dex_files.empty()) {
      error_msgs->push_back("Failed to open dex files from " + source_oat_file->GetLocation());
    } else {
      for (const std::unique_ptr<const DexFile>& dex_file : dex_files) {
        OatDexFile::MadviseDexFile(*dex_file, MadviseState::kMadviseStateAtLoad);
      }
    }
  }

  // 步骤 11: OAT 加载失败，尝试从原始 dex 文件 fallback 加载
  if (dex_files.empty()) {
    if (oat_file_assistant.HasOriginalDexFiles()) {
      if (Runtime::Current()->IsDexFileFallbackEnabled()) {
        static constexpr bool kVerifyChecksum = true;
        const ArtDexFileLoader dex_file_loader;
        if (!dex_file_loader.Open(dex_location,
                                  dex_location,
                                  Runtime::Current()->IsVerificationEnabled(),
                                  kVerifyChecksum,
                                  &error_msg,
                                  &dex_files)) {
          LOG(WARNING) << error_msg;
          error_msgs->push_back("Failed to open dex files from " + std::string(dex_location)
                                + " because: " + error_msg);
        }
      } else {
        error_msgs->push_back("Fallback mode disabled, skipping dex files.");
      }
    } else {
      error_msgs->push_back("No original dex files found for dex location "
          + std::string(dex_location));
    }
  }

  // 步骤 12: JIT 启用时注册 dex 文件
  if (Runtime::Current()->GetJit() != nullptr) {
    ScopedObjectAccess soa(self);
    Runtime::Current()->GetJit()->RegisterDexFiles(
        dex_files, soa.Decode<mirror::ClassLoader>(class_loader));
  }

  // 最终返回 dex 文件数组
  return dex_files;
}
```
[https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/runtime/oat_file_manager.cc;l=447](https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/runtime/oat_file_manager.cc;l=447)



### **OpenCommon**



DexFile_openDexFileNative → DexFile::DexFile 调用路径

```
DexFile_openDexFileNative(...)  
└── OatFileManager::OpenDexFilesFromOat(dex_location, class_loader, dex_elements, out_oat_file, error_msgs)
      └── ArtDexFileLoader::Open(filename, location, verify, verify_checksum, error_msg, dex_files)
            └── art::OpenAndReadMagic(...)
            └── ArtDexFileLoader::OpenWithMagic(...)
            └── ArtDexFileLoader::OpenFile(...)
                   └── ArtDexFileLoader::OpenCommon(base, size, ...)
                          └── DexFileLoader::OpenCommon(base, size, ...)
                                 └── new StandardDexFile(base, location, ...): DexFile(base, location, ...)
                                 └── new CompactDexFile(base, location, ...): DexFile(base, location, ...)
```
[https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/libdexfile/dex/art_dex_file_loader.cc;l=223](https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/libdexfile/dex/art_dex_file_loader.cc;l=223)

[https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/libartbase/base/file_magic.cc?q=OpenAndReadMagic](https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/libartbase/base/file_magic.cc?q=OpenAndReadMagic)



在这些关键 api 当中我们都可以拿到 dex 的起始地址和 size 来进行 dump

```
ArtDexFileLoader::Open(filename, location, verify, verify_checksum, error_msg, dex_files)
   └── ArtDexFileLoader::OpenCommon(base, size, ...)
          └── DexFileLoader::OpenCommon(base, size, ...)
                 └── new StandardDexFile(base, location, ...): DexFile(base, location, ...)
                 └── new CompactDexFile(base, location, ...): DexFile(base, location, ...)
```
[https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/libdexfile/dex/dex_file_loader.cc;l=316](https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/libdexfile/dex/dex_file_loader.cc;l=316)

[https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/libdexfile/dex/standard_dex_file.h;l=100](https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/libdexfile/dex/standard_dex_file.h;l=100)

[https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/libdexfile/dex/dex_file.cc;l=96](https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/libdexfile/dex/dex_file.cc;l=96)



# **通用脱壳点**



所以无论是 InMemoryDexClassLoader 还是 DexClassLoader 加载 Dex 最终都会走到以下方法：

```
ArtDexFileLoader::OpenCommon(base, size, ...)
  └── DexFileLoader::OpenCommon(base, size, ...)
        └── new StandardDexFile(base, location, ...): DexFile(base, location, ...)
        └── new CompactDexFile(base, location, ...): DexFile(base, location, ...)
```
在这些关键 api 当中我们都可以拿到 dex 的起始地址和 size 来进行 dump。



# **OAT 文件**



Android 会在安装应用时，或首次运行时通过 dex2oat 将 .dex 文件转换为 .oat 文件。



OAT 文件是 Android Runtime（ART）生成的优化后的本地代码文件，其全称是 Optimized Android executable。



OAT 文件主要用于：

- 加速应用启动时间

- 减少运行时 JIT 编译压力

- 节省运行时的电量和内存资源



一个 .oat 文件大致包含以下几个部分：

| 部分 | 描述 |
|--- | ---|
| Header | 文件头信息，包括版本、校验等 |
| Dex 文件副本 | 一个或多个原始 .dex 文件的副本 |
| ELF 可执行体 | 编译后的机器代码，和设备架构相关（ARM/ARM64/x86 等） |
| VMap Table | 虚拟寄存器映射表，用于调试和异常恢复 |
| OatMethodData | 每个方法的元数据（偏移、编译类型等） |


根据 Android 版本和架构不同，OAT 文件通常存储在以下目录：

```
/data/app/<package>/oat/arm64/base.odex
/system/framework/boot.oat
/apex/com.android.art/javalib/<*.oat>
```


# **找不到 OpenCommon**



使用 Frida list 一下 art 中的函数



list_module_functions.js

```
function listAllFunctions(moduleName) {
    const baseAddr = Module.findBaseAddress(moduleName);
    if (!baseAddr) {
        console.error(`[-] ${moduleName} not found.`);
        return;
    }

    console.log(`[+] ${moduleName} base address:`, baseAddr);

    const symbols = Module.enumerateSymbolsSync(moduleName);
    let count = 0;

    for (let sym of symbols) {
        if (sym.type === 'function') {
            console.log(`[${count}]`, sym.address, sym.name);
            count++;
        }
    }

    console.log(`[*] Total function symbols found in ${moduleName}:`, count);
}

// 列出 libart.so 的所有函数
setImmediate(function () {
    listAllFunctions("libart.so");
});
```


执行脚本

```
frida -H 127.0.0.1:1234  -F -l list_module_functions.js -o log.txt
```


发现并没有 OpenCommon（LineageOS 17.1，Android 10）



![word/media/image7.png](https://gitee.com/cyrus-studio/images/raw/master/2090c5bd30815303cb2c4f2e6fa4bdb7.png)


进入 adb shell，执行下面命令得到 APP 的  pid 为16418

```
pidof pidof com.cyrus.example
```


查看该进程加载的 libart.so 在什么位置

```
cat /proc/16418/maps | grep libart.so
```


输出如下：

```
7a27617000-7a27744000 r--p 00000000 103:1d 313                           /apex/com.android.runtime/lib64/libart.so
7a27744000-7a27bcf000 --xp 0012d000 103:1d 313                           /apex/com.android.runtime/lib64/libart.so
7a27bcf000-7a27bd2000 rw-p 005b8000 103:1d 313                           /apex/com.android.runtime/lib64/libart.so
7a27bd2000-7a27be3000 r--p 005bb000 103:1d 313                           /apex/com.android.runtime/lib64/libart.so
```


把 libart.so 拉取到本地

```
adb pull /apex/com.android.runtime/lib64/libart.so
```


使用 IDA 打开 libart.so，确实没有 OpenCommon 函数



![word/media/image8.png](https://gitee.com/cyrus-studio/images/raw/master/4683658ba6cf3fc6420618d87bce3b62.png)


# **找到 OpenCommon**



编写一个 Frida 脚本，遍历所有模块的符号，筛选出函数名中包含 "OpenCommon" 或 "DexFileLoader" 的符号，并打印出来（包括模块名、符号名、地址）



find_symbols.js

```
// Frida 脚本：查找所有模块中包含 "OpenCommon" 或 "DexFileLoader" 的函数符号
function scanModulesForKeywords(keywords) {
    const modules = Process.enumerateModules();
    keywords = keywords.map(k => k.toLowerCase());

    for (const module of modules) {
        try {
            const symbols = Module.enumerateSymbols(module.name);
            for (const symbol of symbols) {
                if (symbol.type === 'function') {
                    const lowerName = symbol.name.toLowerCase();
                    if (keywords.some(k => lowerName.includes(k))) {
                        console.log(`[+] ${module.name} -> ${symbol.name} @ ${symbol.address}`);
                    }
                }
            }
        } catch (e) {
            // 某些模块无法枚举，忽略
        }
    }
}

setImmediate(() => {
    console.log("[*] Scanning for symbols containing 'OpenCommon' or 'DexFileLoader' ...");
    scanModulesForKeywords(["OpenCommon", "DexFileLoader"]);
    console.log("[*] Done.");
});


// frida -H 127.0.0.1:1234  -F -l find_symbols.js -o log.txt
```


输出如下：

```
[*] Scanning for symbols containing 'OpenCommon' or 'DexFileLoader' ...
[+] linker64 -> __dl__ZN3art13DexFileLoaderD2Ev @ 0x7aadeac318
[+] linker64 -> __dl__ZN3art13DexFileLoader10OpenCommonEPKhmS2_mRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEEPNS0_12VerifyResultE @ 0x7aadf00370
[+] linker64 -> __dl__ZN3art13DexFileLoader19GetMultiDexLocationEmPKc @ 0x7aadf001c0
[+] linker64 -> __dl__ZN3art13DexFileLoaderD0Ev @ 0x7aadecaef8
[+] linker64 -> __dl__ZNK3art13DexFileLoader19OpenWithDataSectionEPKhmS2_mRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_ @ 0x7aadf00860
[+] linker64 -> __dl__ZNK3art13DexFileLoader20GetMultiDexChecksumsEPKcPNSt3__16vectorIjNS3_9allocatorIjEEEEPNS3_12basic_stringIcNS3_11char_traitsIcEENS5_IcEEEEiPb @ 0x7aadf00288
[+] linker64 -> __dl__ZNK3art13DexFileLoader21OpenOneDexFileFromZipERKNS_13DexZipArchiveEPKcRKNSt3__112basic_stringIcNS6_11char_traitsIcEENS6_9allocatorIcEEEEbbPNS_22DexFileLoaderErrorCodeEPSC_ @ 0x7aadf01128
[+] linker64 -> __dl__ZNK3art13DexFileLoader22OpenAllDexFilesFromZipERKNS_13DexZipArchiveERKNSt3__112basic_stringIcNS4_11char_traitsIcEENS4_9allocatorIcEEEEbbPNS_22DexFileLoaderErrorCodeEPSA_PNS4_6vectorINS4_10unique_ptrIKNS_7DexFileENS4_14default_deleteISJ_EEEENS8_ISM_EEEE @ 0x7aadf00cb8
[+] linker64 -> __dl__ZNK3art13DexFileLoader4OpenEPKhmRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEE @ 0x7aadf002b0
[+] linker64 -> __dl__ZNK3art13DexFileLoader7OpenAllEPKhmRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEbbPNS_22DexFileLoaderErrorCodeEPS9_PNS3_6vectorINS3_10unique_ptrIKNS_7DexFileENS3_14default_deleteISI_EEEENS7_ISL_EEEE @ 0x7aadf00918
[+] libart.so -> _ZN3art13DexFileLoader15GetBaseLocationEPKc @ 0x7a277a1c80
[+] libart.so -> _ZNK3art16ArtDexFileLoader4OpenEPKcRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEbbPS9_PNS3_6vectorINS3_10unique_ptrIKNS_7DexFileENS3_14default_deleteISG_EEEENS7_ISJ_EEEE @ 0x0
[+] libart.so -> _ZNK3art16ArtDexFileLoader4OpenEiRKNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEEbbPS7_PNS1_6vectorINS1_10unique_ptrIKNS_7DexFileENS1_14default_deleteISE_EEEENS5_ISH_EEEE @ 0x0
[+] libart.so -> _ZN3art13DexFileLoader23GetDexCanonicalLocationEPKc @ 0x0
[+] libart.so -> _ZN3art13DexFileLoader18IsMultiDexLocationEPKc @ 0x0
[+] libart.so -> _ZNK3art16ArtDexFileLoader20GetMultiDexChecksumsEPKcPNSt3__16vectorIjNS3_9allocatorIjEEEEPNS3_12basic_stringIcNS3_11char_traitsIcEENS5_IcEEEEiPb @ 0x0
[+] libart.so -> _ZN3art13DexFileLoader19GetMultiDexLocationEmPKc @ 0x0
[+] libart.so -> _ZNK3art16ArtDexFileLoader7OpenZipEiRKNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEEbbPS7_PNS1_6vectorINS1_10unique_ptrIKNS_7DexFileENS1_14default_deleteISE_EEEENS5_ISH_EEEE @ 0x0
[+] libart.so -> _ZN3art13DexFileLoader12IsMagicValidEPKh @ 0x0
[+] libart.so -> _ZN3art13DexFileLoader22IsVersionAndMagicValidEPKh @ 0x0
[+] libart.so -> _ZNK3art16ArtDexFileLoader4OpenEPKhmRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEE @ 0x0
[+] libart.so -> _ZNK3art16ArtDexFileLoader4OpenERKNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEEjONS_6MemMapEbbPS7_ @ 0x0
[+] libart.so -> _ZNK3art13DexFileLoader19OpenWithDataSectionEPKhmS2_mRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_ @ 0x0
[+] libdexfile.so -> _ZN3art13DexFileLoaderD2Ev @ 0x7aac641380
[+] libdexfile.so -> _ZN3art16ArtDexFileLoaderD0Ev @ 0x7aac641388
[+] libdexfile.so -> _ZN3art13DexFileLoader15GetBaseLocationEPKc @ 0x7aac649a78
[+] libdexfile.so -> _ZN3art13DexFileLoaderD0Ev @ 0x7aac641388
[+] libdexfile.so -> _ZN3art13DexFileLoader10OpenCommonEPKhmS2_mRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEEPNS0_12VerifyResultE @ 0x7aac649c28
[+] libdexfile.so -> _ZN3art13DexFileLoader12IsMagicValidEj @ 0x7aac6494f8
[+] libdexfile.so -> _ZN3art13DexFileLoader19GetMultiDexLocationEmPKc @ 0x7aac649668
[+] libdexfile.so -> _ZN3art13DexFileLoader25GetMultiDexClassesDexNameEm @ 0x7aac649620
[+] libdexfile.so -> _ZN3art16ArtDexFileLoader10OpenCommonEPKhmS2_mRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEEPNS_13DexFileLoader12VerifyResultE @ 0x7aac63fc88
[+] libdexfile.so -> _ZNK3art13DexFileLoader19OpenWithDataSectionEPKhmS2_mRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_ @ 0x7aac64a118
[+] libdexfile.so -> _ZNK3art13DexFileLoader7OpenAllEPKhmRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEbbPNS_22DexFileLoaderErrorCodeEPS9_PNS3_6vectorINS3_10unique_ptrIKNS_7DexFileENS3_14default_deleteISI_EEEENS7_ISL_EEEE @ 0x7aac64a1d0
[+] libdexfile.so -> _ZNK3art16ArtDexFileLoader13OpenWithMagicEjiRKNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEEbbPS7_PNS1_6vectorINS1_10unique_ptrIKNS_7DexFileENS1_14default_deleteISE_EEEENS5_ISH_EEEE @ 0x7aac640138
[+] libdexfile.so -> _ZNK3art16ArtDexFileLoader20GetMultiDexChecksumsEPKcPNSt3__16vectorIjNS3_9allocatorIjEEEEPNS3_12basic_stringIcNS3_11char_traitsIcEENS5_IcEEEEiPb @ 0x7aac63f020
[+] libdexfile.so -> _ZNK3art16ArtDexFileLoader21OpenOneDexFileFromZipERKNS_10ZipArchiveEPKcRKNSt3__112basic_stringIcNS6_11char_traitsIcEENS6_9allocatorIcEEEEbbPSC_PNS_22DexFileLoaderErrorCodeE @ 0x7aac640b60
[+] libdexfile.so -> _ZNK3art16ArtDexFileLoader22OpenAllDexFilesFromZipERKNS_10ZipArchiveERKNSt3__112basic_stringIcNS4_11char_traitsIcEENS4_9allocatorIcEEEEbbPSA_PNS4_6vectorINS4_10unique_ptrIKNS_7DexFileENS4_14default_deleteISH_EEEENS8_ISK_EEEE @ 0x7aac6406f0
[+] libdexfile.so -> _ZNK3art16ArtDexFileLoader4OpenEPKcRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEbbPS9_PNS3_6vectorINS3_10unique_ptrIKNS_7DexFileENS3_14default_deleteISG_EEEENS7_ISJ_EEEE @ 0x7aac640058
[+] libdexfile.so -> _ZNK3art16ArtDexFileLoader4OpenEPKhmRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEE @ 0x7aac63fae8
[+] libdexfile.so -> _ZNK3art16ArtDexFileLoader4OpenERKNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEEjONS_6MemMapEbbPS7_ @ 0x7aac63fd10
[+] libdexfile.so -> _ZNK3art16ArtDexFileLoader4OpenEiRKNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEEbbPS7_PNS1_6vectorINS1_10unique_ptrIKNS_7DexFileENS1_14default_deleteISE_EEEENS5_ISH_EEEE @ 0x7aac6403c8
[+] libdexfile.so -> _ZNK3art16ArtDexFileLoader7OpenDexEiRKNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEEbbbPS7_ @ 0x7aac6405e0
[+] libdexfile.so -> _ZNK3art16ArtDexFileLoader7OpenZipEiRKNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEEbbPS7_PNS1_6vectorINS1_10unique_ptrIKNS_7DexFileENS1_14default_deleteISE_EEEENS5_ISH_EEEE @ 0x7aac640490
[+] libdexfile.so -> _ZNK3art16ArtDexFileLoader8OpenFileEiRKNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEEbbbPS7_ @ 0x7aac63f608
[+] libdexfile.so -> _ZN3art13DexFileLoader12IsMagicValidEPKh @ 0x7aac649570
[+] libdexfile.so -> _ZN3art13DexFileLoader18IsMultiDexLocationEPKc @ 0x7aac649600
[+] libdexfile.so -> _ZN3art13DexFileLoader22IsVersionAndMagicValidEPKh @ 0x7aac6495a8
[+] libdexfile.so -> _ZN3art13DexFileLoader23GetDexCanonicalLocationEPKc @ 0x7aac649730
[+] libdexfile.so -> _ZNK3art13DexFileLoader20GetMultiDexChecksumsEPKcPNSt3__16vectorIjNS3_9allocatorIjEEEEPNS3_12basic_stringIcNS3_11char_traitsIcEENS5_IcEEEEiPb @ 0x7aac649b40
[+] libdexfile.so -> _ZNK3art13DexFileLoader21OpenOneDexFileFromZipERKNS_13DexZipArchiveEPKcRKNSt3__112basic_stringIcNS6_11char_traitsIcEENS6_9allocatorIcEEEEbbPNS_22DexFileLoaderErrorCodeEPSC_ @ 0x7aac64a9e0
[+] libdexfile.so -> _ZNK3art13DexFileLoader22OpenAllDexFilesFromZipERKNS_13DexZipArchiveERKNSt3__112basic_stringIcNS4_11char_traitsIcEENS4_9allocatorIcEEEEbbPNS_22DexFileLoaderErrorCodeEPSA_PNS4_6vectorINS4_10unique_ptrIKNS_7DexFileENS4_14default_deleteISJ_EEEENS8_ISM_EEEE @ 0x7aac64a570
[+] libdexfile.so -> _ZNK3art13DexFileLoader4OpenEPKhmRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEE @ 0x7aac649b68
[+] libprofile.so -> _ZN3art13DexFileLoader19GetMultiDexLocationEmPKc @ 0x0
[*] Done.
```


找到 DexFileLoader::OpenCommon 原来在 libdexfile.so

```
[+] libdexfile.so -> _ZN3art13DexFileLoader10OpenCommonEPKhmS2_mRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEEPNS0_12VerifyResultE @ 0x7aac649c28
```
所以 art/runtime/dex_file_loader.cc（DexFileLoader::OpenCommon 实现）最终被编译进 libdexfile.so，而不是 libart.so。



# **OpenCommon 脱壳**



使用 frida hook libdexfile.so 中的 DexFileLoader::OpenCommom 函数并拿到参数 base、size 和 location，把 dex 从内存中 dump 到 /sdcard/Android/data/pkgName/dump_dex 目录下：

```
function getProcessName() {
    var openPtr = Module.getExportByName('libc.so', 'open');
    var open = new NativeFunction(openPtr, 'int', ['pointer', 'int']);

    var readPtr = Module.getExportByName("libc.so", "read");
    var read = new NativeFunction(readPtr, "int", ["int", "pointer", "int"]);

    var closePtr = Module.getExportByName('libc.so', 'close');
    var close = new NativeFunction(closePtr, 'int', ['int']);

    var path = Memory.allocUtf8String("/proc/self/cmdline");
    var fd = open(path, 0);
    if (fd != -1) {
        var buffer = Memory.alloc(0x1000);

        var result = read(fd, buffer, 0x1000);
        close(fd);
        result = ptr(buffer).readCString();
        return result;
    }

    return "-1";
}


function mkdir(path) {
    var mkdirPtr = Module.getExportByName('libc.so', 'mkdir');
    var mkdir = new NativeFunction(mkdirPtr, 'int', ['pointer', 'int']);


    var opendirPtr = Module.getExportByName('libc.so', 'opendir');
    var opendir = new NativeFunction(opendirPtr, 'pointer', ['pointer']);

    var closedirPtr = Module.getExportByName('libc.so', 'closedir');
    var closedir = new NativeFunction(closedirPtr, 'int', ['pointer']);

    var cPath = Memory.allocUtf8String(path);
    var dir = opendir(cPath);
    if (dir != 0) {
        closedir(dir);
        return 0;
    }
    mkdir(cPath, 755);
    chmod(path);
}

function chmod(path) {
    var chmodPtr = Module.getExportByName('libc.so', 'chmod');
    var chmod = new NativeFunction(chmodPtr, 'int', ['pointer', 'int']);
    var cPath = Memory.allocUtf8String(path);
    chmod(cPath, 755);
}

function readStdString(str) {
    const isTiny = (str.readU8() & 1) === 0;
    if (isTiny) {
        return str.add(1).readUtf8String();
    }

    return str.add(2 * Process.pointerSize).readPointer().readUtf8String();
}

function findSymbolInLib(libname, keywordList) {
    const libBase = Module.findBaseAddress(libname);
    if (!libBase) {
        console.error("[-] Library not loaded:", libname);
        return null;
    }

    const matches = [];
    const symbols = Module.enumerateSymbolsSync(libname);
    for (const sym of symbols) {
        if (keywordList.every(k => sym.name.includes(k))) {
            matches.push(sym);
        }
    }

    if (matches.length === 0) {
        console.error("[-] No matching symbol found for keywords:", keywordList);
        return null;
    }

    const target = matches[0]; // 取第一个匹配的
    console.log("[+] Found symbol:", target.name, " @ ", target.address);
    return target.address;
}

function dumpDexToFile(filename, base, size) {
    // packageName
    var processName = getProcessName();

    if (processName != "-1") {
        const dir = "/sdcard/Android/data/" + processName + "/dump_dex";
        const fullPath = dir + "/" + filename.replace(/\//g, "_").replace(/!/g, "_");

        // 创建目录
        mkdir(dir);

        // dump dex
        var fd = new File(fullPath, "wb");
        if (fd && fd != null) {
            var dex_buffer = ptr(base).readByteArray(size);
            fd.write(dex_buffer);
            fd.flush();
            fd.close();
            console.log("[+] Dex dumped to", fullPath);
        }
    }
}


function hookDexFileLoaderOpenCommon() {
    const addr = findSymbolInLib("libdexfile.so", ["DexFileLoader", "OpenCommon"]);
    if (!addr) return;

    Interceptor.attach(addr, {
        onEnter(args) {
            const base = args[0]; // const uint8_t* base
            const size = args[1].toInt32(); // size_t size
            const location_ptr = args[4]; // const std::string& location
            const location = readStdString(location_ptr);

            console.log("\n[*] DexFileLoader::OpenCommon called");
            console.log("    base       :", base);
            console.log("    size       :", size);
            console.log("    location   :", location);

            // 文件名
            const filename = location.split("/").pop();

            // 魔数
            var magic = ptr(base).readCString();
            console.log("    magic      :", magic)

            // dex 格式校验
            if (magic.indexOf("dex") !== -1) {
                dumpDexToFile(filename, base, size)
            }
        },
        onLeave(retval) {}
    });
}

setImmediate(hookDexFileLoaderOpenCommon);
```


列出当前设备所有进程并通过 findstr 过滤出目标进程

```
frida-ps -H 127.0.0.1:1234 | findstr cyrus
```


执行脚本开始 dump

```
frida -H 127.0.0.1:1234 -l dump_dex_from_open_common.js -f com.cyrus.example
```


输出如下：

```
Spawning `com.cyrus.example`...                                         
[+] Found: _ZN3art13DexFileLoader10OpenCommonEPKhmS2_mRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEEPNS0_12VerifyResultE @ 0x7aac649c28
Spawned `com.cyrus.example`. Use %resume to let the main thread start executing!
[Remote::com.cyrus.example]-> %resume
[Remote::com.cyrus.example]-> 
================= DexFileLoader::OpenCommon =================
base: 0x79b9fe106c
size: 1602672
location: /data/app/com.cyrus.example-uIsySv7lFm21qMVPnPJ-pw==/base.apk
magic :  cdex001
processName: com.cyrus.example
[+] Dex dumped to /sdcard/Android/data/com.cyrus.example/dump_dex/base.apk
================= DexFileLoader::OpenCommon =================
base: 0x79ba1684e0
size: 1800
location: /data/app/com.cyrus.example-uIsySv7lFm21qMVPnPJ-pw==/base.apk!classes2.dex
magic :  cdex001
processName: com.cyrus.example
[+] Dex dumped to /sdcard/Android/data/com.cyrus.example/dump_dex/base.apk_classes2.dex
================= DexFileLoader::OpenCommon =================
base: 0x79ba168bec
size: 155888
location: /data/app/com.cyrus.example-uIsySv7lFm21qMVPnPJ-pw==/base.apk!classes3.dex
magic :  cdex001
processName: com.cyrus.example
[+] Dex dumped to /sdcard/Android/data/com.cyrus.example/dump_dex/base.apk_classes3.dex
================= DexFileLoader::OpenCommon =================
base: 0x79ba18ece0
size: 8904
location: /data/app/com.cyrus.example-uIsySv7lFm21qMVPnPJ-pw==/base.apk!classes4.dex
magic :  cdex001
processName: com.cyrus.example
[+] Dex dumped to /sdcard/Android/data/com.cyrus.example/dump_dex/base.apk_classes4.dex
================= DexFileLoader::OpenCommon =================
base: 0x79ba190fac
size: 1288
location: /data/app/com.cyrus.example-uIsySv7lFm21qMVPnPJ-pw==/base.apk!classes5.dex
magic :  cdex001
processName: com.cyrus.example
[+] Dex dumped to /sdcard/Android/data/com.cyrus.example/dump_dex/base.apk_classes5.dex
================= DexFileLoader::OpenCommon =================
base: 0x79ba1914b8
size: 2656
location: /data/app/com.cyrus.example-uIsySv7lFm21qMVPnPJ-pw==/base.apk!classes6.dex
magic :  cdex001
processName: com.cyrus.example
[+] Dex dumped to /sdcard/Android/data/com.cyrus.example/dump_dex/base.apk_classes6.dex
================= DexFileLoader::OpenCommon =================
base: 0x79ba191f1c
size: 11824
location: /data/app/com.cyrus.example-uIsySv7lFm21qMVPnPJ-pw==/base.apk!classes7.dex
magic :  cdex001
processName: com.cyrus.example
[+] Dex dumped to /sdcard/Android/data/com.cyrus.example/dump_dex/base.apk_classes7.dex
================= DexFileLoader::OpenCommon =================
base: 0x79ba194d50
size: 8720
location: /data/app/com.cyrus.example-uIsySv7lFm21qMVPnPJ-pw==/base.apk!classes8.dex
magic :  cdex001
processName: com.cyrus.example
[+] Dex dumped to /sdcard/Android/data/com.cyrus.example/dump_dex/base.apk_classes8.dex
================= DexFileLoader::OpenCommon =================
base: 0x79ba196f64
size: 9472
location: /data/app/com.cyrus.example-uIsySv7lFm21qMVPnPJ-pw==/base.apk!classes9.dex
magic :  cdex001
processName: com.cyrus.example
[+] Dex dumped to /sdcard/Android/data/com.cyrus.example/dump_dex/base.apk_classes9.dex
================= DexFileLoader::OpenCommon =================
base: 0x79ba199468
size: 8904
location: /data/app/com.cyrus.example-uIsySv7lFm21qMVPnPJ-pw==/base.apk!classes10.dex
magic :  cdex001
processName: com.cyrus.example
[+] Dex dumped to /sdcard/Android/data/com.cyrus.example/dump_dex/base.apk_classes10.dex
================= DexFileLoader::OpenCommon =================
base: 0x79ba19b734
size: 9504
location: /data/app/com.cyrus.example-uIsySv7lFm21qMVPnPJ-pw==/base.apk!classes11.dex
magic :  cdex001
processName: com.cyrus.example
[+] Dex dumped to /sdcard/Android/data/com.cyrus.example/dump_dex/base.apk_classes11.dex
================= DexFileLoader::OpenCommon =================
base: 0x79ba19dc58
size: 1632
location: /data/app/com.cyrus.example-uIsySv7lFm21qMVPnPJ-pw==/base.apk!classes12.dex
magic :  cdex001
processName: com.cyrus.example
[+] Dex dumped to /sdcard/Android/data/com.cyrus.example/dump_dex/base.apk_classes12.dex
================= DexFileLoader::OpenCommon =================
base: 0x79ba19e2bc
size: 800
location: /data/app/com.cyrus.example-uIsySv7lFm21qMVPnPJ-pw==/base.apk!classes13.dex
magic :  cdex001
processName: com.cyrus.example
[+] Dex dumped to /sdcard/Android/data/com.cyrus.example/dump_dex/base.apk_classes13.dex
================= DexFileLoader::OpenCommon =================
base: 0x79ba19e5e0
size: 10328
location: /data/app/com.cyrus.example-uIsySv7lFm21qMVPnPJ-pw==/base.apk!classes14.dex
magic :  cdex001
processName: com.cyrus.example
[+] Dex dumped to /sdcard/Android/data/com.cyrus.example/dump_dex/base.apk_classes14.dex
================= DexFileLoader::OpenCommon =================
base: 0x79ba1a0e3c
size: 3016
location: /data/app/com.cyrus.example-uIsySv7lFm21qMVPnPJ-pw==/base.apk!classes15.dex
magic :  cdex001
processName: com.cyrus.example
[+] Dex dumped to /sdcard/Android/data/com.cyrus.example/dump_dex/base.apk_classes15.dex
================= DexFileLoader::OpenCommon =================
base: 0x79ba1a1a08
size: 1205136
location: /data/app/com.cyrus.example-uIsySv7lFm21qMVPnPJ-pw==/base.apk!classes16.dex
magic :  cdex001
processName: com.cyrus.example
[+] Dex dumped to /sdcard/Android/data/com.cyrus.example/dump_dex/base.apk_classes16.dex
```


可以看到 dex 已经 dump 到 sdcard 了



![word/media/image9.png](https://gitee.com/cyrus-studio/images/raw/master/55c0144ce3bb1c5eb7ddff465a5cbfd1.png)


使用下面的 adb pull 命令，一次性将设备上的整个 dump_dex 目录拉取到本地：

```
adb pull /sdcard/Android/data/com.cyrus.example/dump_dex ./dumped_dex
```


但是日志输出的 magic 可以看到都是  cdex001，cdex 文件是不可以直接通过 dex 反编译工具反编译的



![word/media/image10.png](https://gitee.com/cyrus-studio/images/raw/master/c61540418336f940c463dac5f9533c76.png)


# **禁止加载 cdex**



Android 9 引入 CompactDex（.cdex，magic 为 cdex001），是 DEX 的压缩优化版本，导致 dump 后无法直接反编译。



优化后的 dex/cdex 通常存放在：

```
/data/app/package_name/oat/arm64/base.odex
/data/app/package_name/oat/arm64/base.vdex
```


在 Android 9（Pie）中，APP 的 .cdex 文件 是由 dex2oat 优化生成的，通常以 odex, vdex 或直接优化后的 .art 文件形式存在。



进入 adb shell 找到 目标app 存放 oat 文件的路径并删除所有 oat 文件

```
wayne:/sdcard/Android/data/com.cyrus.example/dump_dex # cd /data/app
wayne:/data/app # ls
com.android.chrome-b1d3YEy1eVrwwjPOa1oq5A==       com.iflytek.inputmethod-s1r9JFv0-eKNskzHyrh_vQ==
com.cyrus.example-uIsySv7lFm21qMVPnPJ-pw==        com.shizhuang.duapp-fTxemmnM8l6298xbBELksQ==
com.cyrus.example.plugin-YsXrxPvfWYdsWHxFKjcusw== com.tencent.mm-ql7ajyK9JqKXli5pgu88nw==
com.cyrus.example.test-R06ZNyf5doqJFOcZ6EaYHQ==   com.xingin.xhs-HeYr1dfB-rU7NjxJiLiDeg==
wayne:/data/app # cd com.shizhuang.duapp-fTxemmnM8l6298xbBELksQ==
wayne:/data/app/com.shizhuang.duapp-fTxemmnM8l6298xbBELksQ== # ls
base.apk lib oat
wayne:/data/app/com.shizhuang.duapp-fTxemmnM8l6298xbBELksQ== # cd oat
wayne:/data/app/com.shizhuang.duapp-fTxemmnM8l6298xbBELksQ==/oat # ls
arm64
wayne:/data/app/com.shizhuang.duapp-fTxemmnM8l6298xbBELksQ==/oat # cd arm64/
wayne:/data/app/com.shizhuang.duapp-fTxemmnM8l6298xbBELksQ==/oat/arm64 # ls
base.art base.odex base.vdex
wayne:/data/app/com.shizhuang.duapp-fTxemmnM8l6298xbBELksQ==/oat/arm64 # rm -rf *
```


重新执行 frida 脚本 dump dex，从输出可以看到 dump 下来的 dex 魔数都是 dex 039 / dex 035 （标准 Dex 文件的魔数）不是 cdex001，可以直接用 jadx 去反编译了。

```
Spawning `com.shizhuang.duapp`...                                       
[+] Found symbol: _ZN3art13DexFileLoader10OpenCommonEPKhmS2_mRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEEPNS0_12VerifyResultE  @  0x7aac649c28
Spawned `com.shizhuang.duapp`. Use %resume to let the main thread start executing!
[Remote::com.shizhuang.duapp]-> %resume
[Remote::com.shizhuang.duapp]->
[*] DexFileLoader::OpenCommon called
    base       : 0x7a1d08e02c
    size       : 450032
    location   : /system/framework/org.apache.http.legacy.jar
    magic      : dex
039
[+] Dex dumped to /sdcard/Android/data/com.shizhuang.duapp/dump_dex/org.apache.http.legacy.jar

[*] DexFileLoader::OpenCommon called
    base       : 0x7a1d08e02c
    size       : 450032
    location   : /system/framework/org.apache.http.legacy.jar
    magic      : dex
039
[+] Dex dumped to /sdcard/Android/data/com.shizhuang.duapp/dump_dex/org.apache.http.legacy.jar

[*] DexFileLoader::OpenCommon called
    base       : 0x79bbd5c000
    size       : 8681372
    location   : /data/app/com.shizhuang.duapp-fTxemmnM8l6298xbBELksQ==/base.apk
    magic      : dex
035
[+] Dex dumped to /sdcard/Android/data/com.shizhuang.duapp/dump_dex/base.apk

[*] DexFileLoader::OpenCommon called
    base       : 0x79ba491000
    size       : 12888744
    location   : /data/app/com.shizhuang.duapp-fTxemmnM8l6298xbBELksQ==/base.apk!classes2.dex
    magic      : dex
035
[+] Dex dumped to /sdcard/Android/data/com.shizhuang.duapp/dump_dex/base.apk_classes2.dex

[*] DexFileLoader::OpenCommon called
    base       : 0x79b928e000
    size       : 12592256
    location   : /data/app/com.shizhuang.duapp-fTxemmnM8l6298xbBELksQ==/base.apk!classes3.dex
    magic      : dex
035
[+] Dex dumped to /sdcard/Android/data/com.shizhuang.duapp/dump_dex/base.apk_classes3.dex

[*] DexFileLoader::OpenCommon called
    base       : 0x79b86e8000
    size       : 12213596
    location   : /data/app/com.shizhuang.duapp-fTxemmnM8l6298xbBELksQ==/base.apk!classes4.dex
    magic      : dex
035
[+] Dex dumped to /sdcard/Android/data/com.shizhuang.duapp/dump_dex/base.apk_classes4.dex

[*] DexFileLoader::OpenCommon called
    base       : 0x79b7cc2000
    size       : 10637856
    location   : /data/app/com.shizhuang.duapp-fTxemmnM8l6298xbBELksQ==/base.apk!classes5.dex
    magic      : dex
035
[+] Dex dumped to /sdcard/Android/data/com.shizhuang.duapp/dump_dex/base.apk_classes5.dex

[*] DexFileLoader::OpenCommon called
    base       : 0x79b74d1000
    size       : 8324572
    location   : /data/app/com.shizhuang.duapp-fTxemmnM8l6298xbBELksQ==/base.apk!classes6.dex
    magic      : dex
035
[+] Dex dumped to /sdcard/Android/data/com.shizhuang.duapp/dump_dex/base.apk_classes6.dex

[*] DexFileLoader::OpenCommon called
    base       : 0x79b71b1000
    size       : 3273924
    location   : /data/app/com.shizhuang.duapp-fTxemmnM8l6298xbBELksQ==/base.apk!classes7.dex
    magic      : dex
035
[+] Dex dumped to /sdcard/Android/data/com.shizhuang.duapp/dump_dex/base.apk_classes7.dex

[*] DexFileLoader::OpenCommon called
    base       : 0x79b69e3000
    size       : 8183732
    location   : /data/app/com.shizhuang.duapp-fTxemmnM8l6298xbBELksQ==/base.apk!classes8.dex
    magic      : dex
035
[+] Dex dumped to /sdcard/Android/data/com.shizhuang.duapp/dump_dex/base.apk_classes8.dex

[*] DexFileLoader::OpenCommon called
    base       : 0x79b5e72000
    size       : 11994176
    location   : /data/app/com.shizhuang.duapp-fTxemmnM8l6298xbBELksQ==/base.apk!classes9.dex
    magic      : dex
035
[+] Dex dumped to /sdcard/Android/data/com.shizhuang.duapp/dump_dex/base.apk_classes9.dex

[*] DexFileLoader::OpenCommon called
    base       : 0x79b53d5000
    size       : 11125808
    location   : /data/app/com.shizhuang.duapp-fTxemmnM8l6298xbBELksQ==/base.apk!classes10.dex
    magic      : dex
035
[+] Dex dumped to /sdcard/Android/data/com.shizhuang.duapp/dump_dex/base.apk_classes10.dex

[*] DexFileLoader::OpenCommon called
    base       : 0x79b4815000
    size       : 12319700
    location   : /data/app/com.shizhuang.duapp-fTxemmnM8l6298xbBELksQ==/base.apk!classes11.dex
    magic      : dex
035
[+] Dex dumped to /sdcard/Android/data/com.shizhuang.duapp/dump_dex/base.apk_classes11.dex

[*] DexFileLoader::OpenCommon called
    base       : 0x79b3c59000
    size       : 12300396
    location   : /data/app/com.shizhuang.duapp-fTxemmnM8l6298xbBELksQ==/base.apk!classes12.dex
    magic      : dex
035
[+] Dex dumped to /sdcard/Android/data/com.shizhuang.duapp/dump_dex/base.apk_classes12.dex

[*] DexFileLoader::OpenCommon called
    base       : 0x79b3057000
    size       : 12587972
    location   : /data/app/com.shizhuang.duapp-fTxemmnM8l6298xbBELksQ==/base.apk!classes13.dex
    magic      : dex
035
[+] Dex dumped to /sdcard/Android/data/com.shizhuang.duapp/dump_dex/base.apk_classes13.dex

[*] DexFileLoader::OpenCommon called
    base       : 0x79b24d1000
    size       : 12081268
    location   : /data/app/com.shizhuang.duapp-fTxemmnM8l6298xbBELksQ==/base.apk!classes14.dex
    magic      : dex
035
[+] Dex dumped to /sdcard/Android/data/com.shizhuang.duapp/dump_dex/base.apk_classes14.dex

[*] DexFileLoader::OpenCommon called
    base       : 0x79b18cf000
    size       : 12590752
    location   : /data/app/com.shizhuang.duapp-fTxemmnM8l6298xbBELksQ==/base.apk!classes15.dex
    magic      : dex
035
[+] Dex dumped to /sdcard/Android/data/com.shizhuang.duapp/dump_dex/base.apk_classes15.dex

[*] DexFileLoader::OpenCommon called
    base       : 0x79b179b000
    size       : 1260244
    location   : /data/app/com.shizhuang.duapp-fTxemmnM8l6298xbBELksQ==/base.apk!classes16.dex
    magic      : dex
035
[+] Dex dumped to /sdcard/Android/data/com.shizhuang.duapp/dump_dex/base.apk_classes16.dex

[*] DexFileLoader::OpenCommon called
    base       : 0x79a39f57fc
    size       : 3782924
    location   : /system/product/app/webview/webview.apk
    magic      : dex
035
[+] Dex dumped to /sdcard/Android/data/com.shizhuang.duapp/dump_dex/webview.apk

[*] DexFileLoader::OpenCommon called
    base       : 0x7a11ec6138
    size       : 77880
    location   : /system/product/app/webview/webview.apk!classes2.dex
    magic      : dex
035
[+] Dex dumped to /sdcard/Android/data/com.shizhuang.duapp/dump_dex/webview.apk_classes2.dex

[*] DexFileLoader::OpenCommon called
    base       : 0x79a39f57fc
    size       : 3782924
    location   : /system/product/app/webview/webview.apk
    magic      : dex
035
[+] Dex dumped to /sdcard/Android/data/com.shizhuang.duapp/dump_dex/webview.apk

[*] DexFileLoader::OpenCommon called
    base       : 0x7a11ec6138
    size       : 77880
    location   : /system/product/app/webview/webview.apk!classes2.dex
    magic      : dex
035
[+] Dex dumped to /sdcard/Android/data/com.shizhuang.duapp/dump_dex/webview.apk_classes2.dex
```


# **jadx 反编译 dex**



使用 jadx 反编译 dex。



jadx 项目地址：[https://github.com/skylot/jadx](https://github.com/skylot/jadx)





![word/media/image11.png](https://gitee.com/cyrus-studio/images/raw/master/4816e881ee8000e5b1919e2bff08a6a0.png)


jadx 默认缓存目录

```
C:\Users\$USERNAME\AppData\Local\skylot\jadx\cache\projects
```


# **DexFile 脱壳**



找到 CompactDexFile 构造函数方法符号信息如下：

```
[+] libdexfile.so -> _ZN3art14CompactDexFileC1EPKhmS2_mRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileENS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISG_EEEE @ 0x7aac6420e8
[+] libdexfile.so -> _ZN3art14CompactDexFileC2EPKhmS2_mRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileENS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISG_EEEE @ 0x7aac6420e8
```


hook CompactDexFile 和  StandardDexFile 的构造函数拿到 base、size 和 location 并 dump dex。



dump_dex_from_dex_file.js

```
function getProcessName() {
    var openPtr = Module.getExportByName('libc.so', 'open');
    var open = new NativeFunction(openPtr, 'int', ['pointer', 'int']);

    var readPtr = Module.getExportByName("libc.so", "read");
    var read = new NativeFunction(readPtr, "int", ["int", "pointer", "int"]);

    var closePtr = Module.getExportByName('libc.so', 'close');
    var close = new NativeFunction(closePtr, 'int', ['int']);

    var path = Memory.allocUtf8String("/proc/self/cmdline");
    var fd = open(path, 0);
    if (fd != -1) {
        var buffer = Memory.alloc(0x1000);

        var result = read(fd, buffer, 0x1000);
        close(fd);
        result = ptr(buffer).readCString();
        return result;
    }

    return "-1";
}


function mkdir(path) {
    var mkdirPtr = Module.getExportByName('libc.so', 'mkdir');
    var mkdir = new NativeFunction(mkdirPtr, 'int', ['pointer', 'int']);


    var opendirPtr = Module.getExportByName('libc.so', 'opendir');
    var opendir = new NativeFunction(opendirPtr, 'pointer', ['pointer']);

    var closedirPtr = Module.getExportByName('libc.so', 'closedir');
    var closedir = new NativeFunction(closedirPtr, 'int', ['pointer']);

    var cPath = Memory.allocUtf8String(path);
    var dir = opendir(cPath);
    if (dir != 0) {
        closedir(dir);
        return 0;
    }
    mkdir(cPath, 755);
    chmod(path);
}

function chmod(path) {
    var chmodPtr = Module.getExportByName('libc.so', 'chmod');
    var chmod = new NativeFunction(chmodPtr, 'int', ['pointer', 'int']);
    var cPath = Memory.allocUtf8String(path);
    chmod(cPath, 755);
}

function readStdString(str) {
    const isTiny = (str.readU8() & 1) === 0;
    if (isTiny) {
        return str.add(1).readUtf8String();
    }

    return str.add(2 * Process.pointerSize).readPointer().readUtf8String();
}

function findSymbolInLib(libname, keywordList) {
    const libBase = Module.findBaseAddress(libname);
    if (!libBase) {
        console.error("[-] Library not loaded:", libname);
        return null;
    }

    const matches = [];
    const symbols = Module.enumerateSymbolsSync(libname);
    for (const sym of symbols) {
        if (keywordList.every(k => sym.name.includes(k))) {
            matches.push(sym);
        }
    }

    if (matches.length === 0) {
        console.error("[-] No matching symbol found for keywords:", keywordList);
        return null;
    }

    const target = matches[0]; // 取第一个匹配的
    console.log("[+] Found symbol:", target.name, " @ ", target.address);
    return target.address;
}

function dumpDexToFile(filename, base, size) {
    // packageName
    var processName = getProcessName();

    if (processName != "-1") {
        const dir = "/sdcard/Android/data/" + processName + "/dump_dex";
        const fullPath = dir + "/" + filename.replace(/\//g, "_").replace(/!/g, "_");

        // 创建目录
        mkdir(dir);

        // dump dex
        var fd = new File(fullPath, "wb");
        if (fd && fd != null) {
            var dex_buffer = ptr(base).readByteArray(size);
            fd.write(dex_buffer);
            fd.flush();
            fd.close();
            console.log("[+] Dex dumped to", fullPath);
        }
    }
}

function hookCompactDexFile() {
    const addr = findSymbolInLib("libdexfile.so", ["CompactDexFile", "C1"]);
    if (!addr) return;

    Interceptor.attach(addr, {
        onEnter(args) {
            const base = args[1];
            const size = args[2].toInt32();
            const data_base = args[3];
            const data_size = args[4].toInt32();
            const location_ptr = args[5];
            const location = readStdString(location_ptr);

            console.log("\n[*] CompactDexFile constructor called");
            console.log("    this       :", args[0]);
            console.log("    base       :", base);
            console.log("    size       :", size);
            console.log("    data_base  :", data_base);
            console.log("    data_size  :", data_size);
            console.log("    location   :", location);

            // 文件名
            const filename = location.split("/").pop();

            // 魔数
            var magic = ptr(base).readCString();
            console.log("    magic      :", magic)

            // dex 格式校验
            if (magic.indexOf("dex") !== -1) {
                dumpDexToFile(filename, base, size)
            }
        }
    });
}

function hookStandardDexFile() {
    const addr = findSymbolInLib("libdexfile.so", ["StandardDexFile", "C1"]);
    if (!addr) return;

    Interceptor.attach(addr, {
        onEnter(args) {
            const base = args[1];
            const size = args[2].toInt32();
            const data_base = args[3];
            const data_size = args[4].toInt32();
            const location_ptr = args[5];
            const location = readStdString(location_ptr);

            console.log("\n[*] StandardDexFile constructor called");
            console.log("    this       :", args[0]);
            console.log("    base       :", base);
            console.log("    size       :", size);
            console.log("    data_base  :", data_base);
            console.log("    data_size  :", data_size);
            console.log("    location   :", location);

            // 文件名
            const filename = location.split("/").pop();

            // 魔数
            var magic = ptr(base).readCString();
            console.log("    magic      :", magic)

            // dex 格式校验
            if (magic.indexOf("dex") !== -1) {
                dumpDexToFile(filename, base, size)
            }
        }
    });
}


setImmediate(function () {
    hookCompactDexFile()
    hookStandardDexFile()
});
```


执行脚本：

```
frida -H 127.0.0.1:1234 -l dump_dex_from_dex_file.js -f com.cyrus.example
```


输出如下：

```
Spawning `com.cyrus.example`...                                         
[+] Found symbol: _ZN3art14CompactDexFileC1EPKhmS2_mRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileENS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISG_EEEE  @  0x7aac6420e8
[-] No matching symbol found for keywords: StandardDexFile,C1
Spawned `com.cyrus.example`. Use %resume to let the main thread start executing!
[Remote::com.cyrus.example]-> %resume
[Remote::com.cyrus.example]->
[*] CompactDexFile constructor called
    this       : 0x7aacac0720
    base       : 0x79b9fe206c
    size       : 1602672
    data_base  : 0x79ba2c8d98
    data_size  : 14765976
    location   : /data/app/com.cyrus.example-uIsySv7lFm21qMVPnPJ-pw==/base.apk
    magic      : cdex001
[+] Dex dumped to /sdcard/Android/data/com.cyrus.example/dump_dex/base.apk

[*] CompactDexFile constructor called
    this       : 0x7aacac0800
    base       : 0x79ba1694e0
    size       : 1800
    data_base  : 0x79ba2c8d98
    data_size  : 14770144
    location   : /data/app/com.cyrus.example-uIsySv7lFm21qMVPnPJ-pw==/base.apk!classes2.dex
    magic      : cdex001
[+] Dex dumped to /sdcard/Android/data/com.cyrus.example/dump_dex/base.apk_classes2.dex

[*] CompactDexFile constructor called
    this       : 0x7aacac08e0
    base       : 0x79ba169bec
    size       : 155888
    data_base  : 0x79ba2c8d98
    data_size  : 15120528
    location   : /data/app/com.cyrus.example-uIsySv7lFm21qMVPnPJ-pw==/base.apk!classes3.dex
    magic      : cdex001
[+] Dex dumped to /sdcard/Android/data/com.cyrus.example/dump_dex/base.apk_classes3.dex

[*] CompactDexFile constructor called
    this       : 0x7aacac09c0
    base       : 0x79ba18fce0
    size       : 8904
    data_base  : 0x79ba2c8d98
    data_size  : 15155776
    location   : /data/app/com.cyrus.example-uIsySv7lFm21qMVPnPJ-pw==/base.apk!classes4.dex
    magic      : cdex001
[+] Dex dumped to /sdcard/Android/data/com.cyrus.example/dump_dex/base.apk_classes4.dex

[*] CompactDexFile constructor called
    this       : 0x7aacac0aa0
    base       : 0x79ba191fac
    size       : 1288
    data_base  : 0x79ba2c8d98
    data_size  : 15158304
    location   : /data/app/com.cyrus.example-uIsySv7lFm21qMVPnPJ-pw==/base.apk!classes5.dex
    magic      : cdex001
[+] Dex dumped to /sdcard/Android/data/com.cyrus.example/dump_dex/base.apk_classes5.dex

[*] CompactDexFile constructor called
    this       : 0x7aacac0b80
    base       : 0x79ba1924b8
    size       : 2656
    data_base  : 0x79ba2c8d98
    data_size  : 15165016
    location   : /data/app/com.cyrus.example-uIsySv7lFm21qMVPnPJ-pw==/base.apk!classes6.dex
    magic      : cdex001
[+] Dex dumped to /sdcard/Android/data/com.cyrus.example/dump_dex/base.apk_classes6.dex

[*] CompactDexFile constructor called
    this       : 0x7aacac0c60
    base       : 0x79ba192f1c
    size       : 11824
    data_base  : 0x79ba2c8d98
    data_size  : 15211952
    location   : /data/app/com.cyrus.example-uIsySv7lFm21qMVPnPJ-pw==/base.apk!classes7.dex
    magic      : cdex001
[+] Dex dumped to /sdcard/Android/data/com.cyrus.example/dump_dex/base.apk_classes7.dex

[*] CompactDexFile constructor called
    this       : 0x7aacac0d40
    base       : 0x79ba195d50
    size       : 8720
    data_base  : 0x79ba2c8d98
    data_size  : 15242288
    location   : /data/app/com.cyrus.example-uIsySv7lFm21qMVPnPJ-pw==/base.apk!classes8.dex
    magic      : cdex001
[+] Dex dumped to /sdcard/Android/data/com.cyrus.example/dump_dex/base.apk_classes8.dex

[*] CompactDexFile constructor called
    this       : 0x7a175fe260
    base       : 0x79ba197f64
    size       : 9472
    data_base  : 0x79ba2c8d98
    data_size  : 15276888
    location   : /data/app/com.cyrus.example-uIsySv7lFm21qMVPnPJ-pw==/base.apk!classes9.dex
    magic      : cdex001
[+] Dex dumped to /sdcard/Android/data/com.cyrus.example/dump_dex/base.apk_classes9.dex

[*] CompactDexFile constructor called
    this       : 0x7a175fe340
    base       : 0x79ba19a468
    size       : 8904
    data_base  : 0x79ba2c8d98
    data_size  : 15314648
    location   : /data/app/com.cyrus.example-uIsySv7lFm21qMVPnPJ-pw==/base.apk!classes10.dex
    magic      : cdex001
[+] Dex dumped to /sdcard/Android/data/com.cyrus.example/dump_dex/base.apk_classes10.dex

[*] CompactDexFile constructor called
    this       : 0x7a175fe420
    base       : 0x79ba19c734
    size       : 9504
    data_base  : 0x79ba2c8d98
    data_size  : 15346672
    location   : /data/app/com.cyrus.example-uIsySv7lFm21qMVPnPJ-pw==/base.apk!classes11.dex
    magic      : cdex001
[+] Dex dumped to /sdcard/Android/data/com.cyrus.example/dump_dex/base.apk_classes11.dex

[*] CompactDexFile constructor called
    this       : 0x7a175fe500
    base       : 0x79ba19ec58
    size       : 1632
    data_base  : 0x79ba2c8d98
    data_size  : 15349816
    location   : /data/app/com.cyrus.example-uIsySv7lFm21qMVPnPJ-pw==/base.apk!classes12.dex
    magic      : cdex001
[+] Dex dumped to /sdcard/Android/data/com.cyrus.example/dump_dex/base.apk_classes12.dex

[*] CompactDexFile constructor called
    this       : 0x7a175fe5e0
    base       : 0x79ba19f2bc
    size       : 800
    data_base  : 0x79ba2c8d98
    data_size  : 15350936
    location   : /data/app/com.cyrus.example-uIsySv7lFm21qMVPnPJ-pw==/base.apk!classes13.dex
    magic      : cdex001
[+] Dex dumped to /sdcard/Android/data/com.cyrus.example/dump_dex/base.apk_classes13.dex

[*] CompactDexFile constructor called
    this       : 0x7a175fe6c0
    base       : 0x79ba19f5e0
    size       : 10328
    data_base  : 0x79ba2c8d98
    data_size  : 15401760
    location   : /data/app/com.cyrus.example-uIsySv7lFm21qMVPnPJ-pw==/base.apk!classes14.dex
    magic      : cdex001
[+] Dex dumped to /sdcard/Android/data/com.cyrus.example/dump_dex/base.apk_classes14.dex

[*] CompactDexFile constructor called
    this       : 0x7a176a4fc0
    base       : 0x79ba1a1e3c
    size       : 3016
    data_base  : 0x79ba2c8d98
    data_size  : 15409648
    location   : /data/app/com.cyrus.example-uIsySv7lFm21qMVPnPJ-pw==/base.apk!classes15.dex
    magic      : cdex001
[+] Dex dumped to /sdcard/Android/data/com.cyrus.example/dump_dex/base.apk_classes15.dex

[*] CompactDexFile constructor called
    this       : 0x7a176a50a0
    base       : 0x79ba1a2a08
    size       : 1205136
    data_base  : 0x79ba2c8d98
    data_size  : 22612744
    location   : /data/app/com.cyrus.example-uIsySv7lFm21qMVPnPJ-pw==/base.apk!classes16.dex
    magic      : cdex001
[+] Dex dumped to /sdcard/Android/data/com.cyrus.example/dump_dex/base.apk_classes16.dex
```


把 dex 文件拉取到本地：

```
adb pull /sdcard/Android/data/com.cyrus.example/dump_dex ./dumped_dex
```


使用命令行工具 compact_dex_converter 把 cdex（Compact Dex）文件转换为标准 .dex 文件。

[https://github.com/anestisb/vdexExtractor#compact-dex-converter](https://github.com/anestisb/vdexExtractor#compact-dex-converter)



# **dex2oat 脱壳**



dex2oat 的流程也可以进行脱壳。



当安装 APK 时，如果需要 ahead-of-time (AOT) 编译，installd 会调用 dex2oat：



![word/media/image12.png](https://gitee.com/cyrus-studio/images/raw/master/608956255740c4fefcd613ee1b52900c.png)
[https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:frameworks/native/cmds/installd/dexopt.cpp;l=306](https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:frameworks/native/cmds/installd/dexopt.cpp;l=306)



进入 dex2oat.cc 的 main()，在 dex2oat::ReturnCode Setup() 方法中 将 dex 注册到 VerificationResults 时候可以拿到 dex_file 对象，这里也是一个很好的脱壳点。

```
verification_results_->AddDexFile(dex_file);
```


![word/media/image13.png](https://gitee.com/cyrus-studio/images/raw/master/4a384bd1e48d829f9c6064b9d1299864.png)
[https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/dex2oat/dex2oat.cc;l=1685](https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/dex2oat/dex2oat.cc;l=1685)



# **完整源码**



开源地址：[https://github.com/CYRUS-STUDIO/frida_dex_dump](https://github.com/CYRUS-STUDIO/frida_dex_dump)



相关文章：

- _[ART环境下dex加载流程分析及frida dump dex方案](https://bbs.kanxue.com/thread-277771.htm)_

- _[拨云见日：安卓APP脱壳的本质以及如何快速发现ART下的脱壳点](https://bbs.kanxue.com/thread-254555.htm)_




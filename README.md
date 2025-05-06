> Авторские права принадлежат автору, при перепечатке указывайте источник статьи: <https://cyrus-studio.github.io/blog/>

# **DEF CON**



DEF CON - одна из крупнейших в мире конференций по компьютерной безопасности (Оскар для гиков), которая проводится ежегодно в Лас-Вегасе, штат Невада, с июня 1993 года.



Официальный сайт: [https://media.defcon.org/](https://media.defcon.org/), официальный сайт медиа-архива конференции DEF CON, предлагает бесплатное скачивание публичных выступлений, слайдов, видео, аудио, примеров кода и других связанных ресурсов с прошлых конференций DEF CON.



На DEF CON 25 (2017 год) исследователи безопасности из Check Point Слава Маккавиев и Ави Башан выступили с докладом "Unboxing Android: Everything You Wanted to Know About Android Packers", в котором подробно рассмотрели технологии упаковки приложений Android и их влияние на безопасность.



Адрес файла отчета:

[https://media.defcon.org/DEF%20CON%2025/DEF%20CON%2025%20presentations/DEF%20CON%2025%20-%20Slava-Makkaveev-and-Avi-Bashan-Unboxing-Android.pdf](https://media.defcon.org/DEF%20CON%2025/DEF%20CON%2025%20presentations/DEF%20CON%2025%20-%20Slava-Makkaveev-and-Avi-Bashan-Unboxing-Android.pdf)



Также есть анализ китайских производителей упаковки



![word/media/image1.png](https://gitee.com/cyrus-studio/images/raw/master/85777d44ae42a2c7de18295d01712c01.png)


Исследователи безопасности DEF выбрали две точки для распаковки: art::OpenAndReadMagic и DexFile::DexFile



![word/media/image2.png](https://gitee.com/cyrus-studio/images/raw/master/26614f34fc11c05f376afdac726283da.png)


# **Unboxing Android**



На DEF CON 25 (2017) Ави Башан и Слава Маккавиев предложили очень практичную технику распаковки приложений Android:



Изменяя конструктор DexFile::DexFile() и метод OpenAndReadMagic(), можно перехватить процесс загрузки DEX-файлов во время выполнения приложения, чтобы получить расшифрованные данные из памяти и завершить распаковку.



## **1. Конструктор DexFile::DexFile**



Можно увидеть, что параметры конструктора DexFile::DexFile() включают:

- const uint8_t* base — начальный адрес DEX в памяти

- size_t size — размер DEX в памяти

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


Пример вставки кода для распаковки

```
// Печать текущего местоположения DEX-файла
LOG(WARNING) << "Dex File: Filename: " << location;

// Проверка, загружается ли этот DEX из собственного приватного каталога приложения.
// Поскольку DEX-файлы из системных фреймворков и boot.oat не являются упакованными DEX, мы хотим только распаковать DEX-файлы приложения.
if (location.find("/data/data/") != std::string::npos) {
    LOG(WARNING) << "Dex File: OAT file unpacking launched";

    // Создание нового файла, например /data/data/пакет/xxx.dex__unpacked_oat.
    std::ofstream dst(location + "__unpacked_oat", std::ios::binary);
    // Запись данных DEX из памяти на диск.
    dst.write(reinterpret_cast<const char*>(base), size);
    // Сохранение файла, завершение распаковки.
    dst.close();
} else {
    LOG(WARNING) << "Dex File: OAT file unpacking not launched";
}
```


## **2. DexFile::OpenAndReadMagic()**



Это вспомогательная функция для проверки заголовка DEX-файла.

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


Пример вставки кода для распаковки

```
struct stat st;  // Для получения информации о размере файла и т.д.

// Печать текущего обрабатываемого пути файла для отладки и наблюдения за источником загружаемого DEX
LOG(WARNING) << "File_magic: Filename: " << filename;

// Обработка только файлов в пути /data/data (т.е. DEX-файлов в приватном каталоге приложения)
// Это позволяет избежать обработки системных DEX, повышая эффективность и точность
if (strstr(filename, "/data/data") != NULL) {
  LOG(WARNING) << "File_magic: DEX file unpacking launched";

  // Создание пути к выходному файлу с добавлением суффикса "__unpacked_dex"
  char* fn_out = new char[PATH_MAX];
  strcpy(fn_out, filename);
  strcat(fn_out, "__unpacked_dex");

  // Создание выходного файла с правами: пользователь может читать и записывать, группа пользователей может читать, другие могут читать
  int fd_out = open(fn_out, O_WRONLY | O_CREAT | O_EXCL,
                    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

  // Если успешно получена информация о исходном DEX-файле (для получения размера файла)
  if (!fstat(fd.get(), &st)) {
    // Использование mmap для отображения всего DEX-файла в память
    char* addr = (char*)mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd.get(), 0);

    // Запись содержимого из памяти в новый файл, завершение дампа DEX на уровне диска
    int ret = write(fd_out, addr, st.st_size);

    // Опциональный код для предотвращения оптимизации (гарантирует использование ret, предотвращая оптимизацию компилятора)
    ret += 1;

    // Освобождение отображения, освобождение памяти
    munmap(addr, st.st_size);
  }

  // Закрытие выходного файла, очистка памяти пути
  close(fd_out);
  delete[] fn_out;

} else {
  // Если файл не находится в приватном пути приложения, пропуск обработки
  LOG(WARNING) << "File_magic: DEX file unpacking not launched";
}
```


# **Принцип распаковки под ART**



Два распространенных загрузчика dex под ART: InMemoryDexClassLoader и DexClassLoader



## **Анализ исходного кода InMemoryDexClassLoader**



InMemoryDexClassLoader - это класс, введенный в Android 8.0 (API уровень 26), который используется для динамической загрузки Dex из памяти.



Пример вызова:

```
// Предположим, что dexBytes - это содержимое вашего DEX-файла (может быть получено путем расшифровки)
ByteBuffer buffer = ByteBuffer.wrap(dexBytes);

// Создание InMemoryDexClassLoader
ClassLoader loader = new InMemoryDexClassLoader(buffer, ClassLoader.getSystemClassLoader());

// Загрузка класса через рефлексию и вызов метода
Class<?> clazz = loader.loadClass("com.example.MyHiddenClass");
Method m = clazz.getDeclaredMethod("secretMethod");
m.invoke(null);
```


InMemoryDexClassLoader поддерживает загрузку одного или нескольких Dex из памяти. Исходный код выглядит следующим образом:



![word/media/image5.png](https://gitee.com/cyrus-studio/images/raw/master/882c2733141420f573b56a73a7166520.png)
[https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:libcore/dalvik/src/main/java/dalvik/system/InMemoryDexClassLoader.java](https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:libcore/dalvik/src/main/java/dalvik/system/InMemoryDexClassLoader.java)



### **openInMemoryDexFilesNative**



Процесс загрузки Dex выглядит следующим образом, в конечном итоге вызывается native метод openInMemoryDexFilesNative

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



В методе DexFile_openInMemoryDexFilesNative вызывается метод OpenDexFilesFromOat для загрузки Dex:

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

  // Выделение памяти для dex-файлов и копирование данных из ByteBuffers.
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
      // Прямой ByteBuffer
      uint8_t* base_address = reinterpret_cast<uint8_t*>(env->GetDirectBufferAddress(buffer));
      if (base_address == nullptr) {
        ScopedObjectAccess soa(env);
        ThrowWrappedIOException("dexFileBuffer not direct");
        return nullptr;
      }
      size_t length = static_cast<size_t>(end - start);
      memcpy(dex_data.Begin(), base_address + start, length);
    } else {
      // ByteBuffer, поддерживаемый массивом байтов
      jbyte* destination = reinterpret_cast<jbyte*>(dex_data.Begin());
      env->GetByteArrayRegion(array, start, end - start, destination);
    }

    dex_mem_maps.push_back(std::move(dex_data));
  }

  // Передача MemMaps в OatFileManager для открытия dex-файлов и потенциального создания резервного экземпляра OatFile из анонимного vdex.
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



Метод OpenDexFilesFromOat вызывает метод OpenDexFilesFromOat_Impl для загрузки Dex

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

  // [1] Извлечение заголовка Dex для последующей проверки контрольной суммы, генерации пути и т.д.
  const std::vector<const DexFile::Header*> dex_headers = GetDexFileHeaders(dex_mem_maps);

  // [2] Генерация временного анонимного пути к файлам dex/vdex, получение контрольной суммы и пути
  uint32_t location_checksum;
  std::string dex_location;
  std::string vdex_path;
  bool has_vdex = OatFileAssistant::AnonymousDexVdexLocation(
      dex_headers, kRuntimeISA, &location_checksum, &dex_location, &vdex_path);

  // [3] Попытка открыть файл vdex и проверить, совпадают ли контрольные суммы dex
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

  // [4] Загрузка dex из памяти. Если vdex существует и проверка прошла успешно, можно пропустить проверку структуры
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
      dex::tracking::RegisterDexFile(dex_file.get());  // Регистрация для отладки и отслеживания
      dex_files.push_back(std::move(dex_file));
    } else {
      error_msgs->push_back("Failed to open dex files from memory: " + error_msg);
    }
  }

  // [5] Если vdex не существует, загрузка не удалась или class_loader пуст, возвращаем dex_files
  if (vdex_file == nullptr || class_loader == nullptr || !error_msgs->empty()) {
    return dex_files;
  }

  // [6] Создание ClassLoaderContext, чтобы обеспечить一致ность контекста загрузки oat
  std::unique_ptr<ClassLoaderContext> context = ClassLoaderContext::CreateContextForClassLoader(
      class_loader, dex_elements);
  if (context == nullptr) {
    LOG(ERROR) << "Could not create class loader context for " << vdex_path;
    return dex_files;
  }
  DCHECK(context->OpenDexFiles(kRuntimeISA, ""))
      << "Context created from already opened dex files should not attempt to open again";

  // [7] Проверка контрольных сумм boot class path и соответствия контекста class loader
  if (!vdex_file->MatchesBootClassPathChecksums() ||
      !vdex_file->MatchesClassLoaderContext(*context.get())) {
    return dex_files;
  }

  // [8] Создание экземпляра OatFile из vdex и регистрация
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



До Android 10, DEX-файлы, загруженные InMemoryDexClassLoader, не компилировались в OAT-файлы, а выполнялись в режиме интерпретации, что отличает его от DexClassLoader.



С Android 10, DEX-файлы, загруженные InMemoryDexClassLoader, также проходят через процесс OAT.



Путь вызова DexFile_openInMemoryDexFilesNative → DexFile::DexFile

```
DexFile_openInMemoryDexFilesNative(...)                    
└── AllocateDexMemoryMap(...) Создание dex_mem_maps
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



В этих ключевых API мы можем получить начальный адрес и размер dex для дампа

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



## **Анализ исходного кода DexClassLoader**



DexClassLoader может загружать dex из любого пути, а также jar, apk, zip файлы (содержащие classes.dex).



Исходный код выглядит следующим образом:



![word/media/image6.png](https://gitee.com/cyrus-studio/images/raw/master/05532442ff68769ffc74626f16ea0ad9.png)
[https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:libcore/dalvik/src/main/java/dalvik/system/DexClassLoader.java](https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:libcore/dalvik/src/main/java/dalvik/system/DexClassLoader.java)



### **DexFile_openDexFileNative**



DexClassLoader в конечном итоге вызывает JNI метод DexFile_openDexFileNative для загрузки Dex.



Ниже приведен полный путь вызова от Java до native (на примере Android 10):

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
DexFile_openDexFileNative(...) (native уровень)
```
[https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:libcore/dalvik/src/main/java/dalvik/system/DexFile.java;l=440](https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:libcore/dalvik/src/main/java/dalvik/system/DexFile.java;l=440)



В методе DexFile_openDexFileNative вызывается метод OpenDexFilesFromOat для создания OAT-файла:

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



В отличие от InMemoryDexClassLoader, здесь передается не MemMap, а const char* dex_location.



Исходный код метода OpenDexFilesFromOat выглядит следующим образом:

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

  // Шаг 1: Убедиться, что не удерживается mutator_lock, чтобы предотвратить блокировку GC
  Thread* const self = Thread::Current();
  Locks::mutator_lock_->AssertNotHeld(self);
  Runtime* const runtime = Runtime::Current();

  // Шаг 2: Создание ClassLoaderContext (может быть пустым)
  std::unique_ptr<ClassLoaderContext> context;
  if (class_loader == nullptr) {
    LOG(WARNING) << "Opening an oat file without a class loader. "
                 << "Are you using the deprecated DexFile APIs?";
    context = nullptr;
  } else {
    context = ClassLoaderContext::CreateContextForClassLoader(class_loader, dex_elements);
  }

  // Шаг 3: Создание OatFileAssistant для работы с oat и dex файлами
  OatFileAssistant oat_file_assistant(dex_location,
                                      kRuntimeISA,
                                      !runtime->IsAotCompiler(),
                                      only_use_system_oat_files_);

  // Шаг 4: Получение лучшего OAT-файла на диске
  std::unique_ptr<const OatFile> oat_file(oat_file_assistant.GetBestOatFile().release());
  VLOG(oat) << "OatFileAssistant(" << dex_location << ").GetBestOatFile()="
            << reinterpret_cast<uintptr_t>(oat_file.get())
            << " (executable=" << (oat_file != nullptr ? oat_file->IsExecutable() : false) << ")";

  const OatFile* source_oat_file = nullptr;
  CheckCollisionResult check_collision_result = CheckCollisionResult::kPerformedHasCollisions;
  std::string error_msg;

  // Шаг 5: Проведение проверки на коллизии для решения, принимать ли этот oat файл
  if ((class_loader != nullptr || dex_elements != nullptr) && oat_file != nullptr) {
    check_collision_result = CheckCollision(oat_file.get(), context.get(), &error_msg);
    bool accept_oat_file = AcceptOatFile(check_collision_result);

    // Если результат проверки false, определить, включен ли fallback, и записать предупреждающую информацию
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

    // Шаг 6: Регистрация oat файла в OatFileManager
    if (accept_oat_file) {
      VLOG(class_linker) << "Registering " << oat_file->GetLocation();
      source_oat_file = RegisterOatFile(std::move(oat_file));
      *out_oat_file = source_oat_file;
    }
  }

  std::vector<std::unique_ptr<const DexFile>> dex_files;

  // Шаг 7: Загрузка dex файлов из OAT файла (если oat успешно загружен)
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

        // Шаг 8: Попытка добавить image space в heap
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

    // Шаг 9: Если image space не добавлено, загрузка dex файлов вручную из oat
    if (!added_image_space) {
      DCHECK(dex_files.empty());
      dex_files = oat_file_assistant.LoadDexFiles(*source_oat_file, dex_location);

      for (const auto& dex_file : dex_files) {
        dex::tracking::RegisterDexFile(dex_file.get());
      }
    }

    // Шаг 10: Проверка, не произошла ли ошибка загрузки dex файлов
    if (dex_files.empty()) {
      error_msgs->push_back("Failed to open dex files from " + source_oat_file->GetLocation());
    } else {
      for (const std::unique_ptr<const DexFile>& dex_file : dex_files) {
        OatDexFile::MadviseDexFile(*dex_file, MadviseState::kMadviseStateAtLoad);
      }
    }
  }

  // Шаг 11: Если загрузка OAT не удалась, попытка загрузки из оригинального dex файла
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

  // Шаг 12: При включенном JIT регистрация dex файлов
  if (Runtime::Current()->GetJit() != nullptr) {
    ScopedObjectAccess soa(self);
    Runtime::Current()->GetJit()->RegisterDexFiles(
        dex_files, soa.Decode<mirror::ClassLoader>(class_loader));
  }

  // Возвращение массива dex файлов
  return dex_files;
}
```
[https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/runtime/oat_file_manager.cc;l=447](https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/runtime/oat_file_manager.cc;l=447)



### **OpenCommon**



Путь вызова DexFile_openDexFileNative → DexFile::DexFile

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
[https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/libdexfile/dex/art_dex_file_loader.cc;l=223](https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/libartbase/base/file_magic.cc?q=OpenAndReadMagic](https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/libartbase/base/file_magic.cc?q=OpenAndReadMagic)



В этих ключевых API мы можем получить начальный адрес и размер dex для дампа

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



# **Универсальные точки для распаковки**



Таким образом, независимо от того, используется ли InMemoryDexClassLoader или DexClassLoader для загрузки Dex, в конечном итоге они будут обращаться к следующим методам:

```
ArtDexFileLoader::OpenCommon(base, size, ...)
  └── DexFileLoader::OpenCommon(base, size, ...)
        └── new StandardDexFile(base, location, ...): DexFile(base, location, ...)
        └── new CompactDexFile(base, location, ...): DexFile(base, location, ...)
```
В этих ключевых API мы можем получить начальный адрес и размер dex для дампа.



# **OAT файлы**



Android при установке приложения или при первом запуске использует dex2oat для преобразования .dex файлов в .oat файлы.



OAT файл - это оптимизированный исполняемый файл Android, созданный Android Runtime (ART), его полное название - Optimized Android executable.



OAT файл используется для:

- Ускорения времени запуска приложения

- Снижения нагрузки на JIT компиляцию во время выполнения

- Экономии энергии и ресурсов памяти во время выполнения



Один .oat файл обычно содержит следующие части:

| Часть | Описание |
|--- | ---|
| Заголовок | Информация о заголовке файла, включая версию, проверку и т.д. |
| Копия Dex файла | Одна или несколько копий оригинальных .dex файлов |
| ELF исполняемый файл | Скомпилированный машинный код, связанный с архитектурой устройства (ARM/ARM64/x86 и т.д.) |
| VMap таблица | Таблица отображения виртуальных регистров, используемая для отладки и восстановления после исключений |
| OatMethodData | Метаданные для каждого метода (смещение, тип компиляции и т.д.) |


В зависимости от версии Android и архитектуры, OAT файлы обычно хранятся в следующих каталогах:

```
/data/app/<package>/oat/arm64/base.odex
/system/framework/boot.oat
/apex/com.android.art/javalib/<*.oat>
```


# **Не удается найти OpenCommon**



Используйте Frida для перечисления функций в art



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

// Перечисление всех функций в libart.so
setImmediate(function () {
    listAllFunctions("libart.so");
});
```


Выполнение скрипта

```
frida -H 127.0.0.1:1234  -F -l list_module_functions.js -o log.txt
```


Обнаружено, что нет функции OpenCommon (LineageOS 17.1, Android 10)



![word/media/image7.png](https://gitee.com/cyrus-studio/images/raw/master/2090c5bd30815303cb2c4f2e6fa4bdb7.png)


Войдите в adb shell и выполните следующую команду, чтобы получить pid приложения 16418

```
pidof pidof com.cyrus.example
```


Проверьте, где загружен libart.so в этом процессе

```
cat /proc/16418/maps | grep libart.so
```


Вывод следующий:

```
7a27617000-7a27744000 r--p 00000000 103:1d 313                           /apex/com.android.runtime/lib64/libart.so
7a27744000-7a27bcf000 --xp 0012d000 103:1d 313                           /apex/com.android.runtime/lib64/libart.so
7a27bcf000-7a27bd2000 rw-p 005b8000 103:1d 313                           /apex/com.android.runtime/lib64/libart.so
7a27bd2000-7a27be3000 r--p 005bb000 103:1d 313                           /apex/com.android.runtime/lib64/libart.so
```


Скопируйте libart.so на локальный компьютер

```
adb pull /apex/com.android.runtime/lib64/libart.so
```


Используйте IDA для открытия libart.so, действительно нет функции OpenCommon



![word/media/image8.png](https://gitee.com/cyrus-studio/images/raw/master/4683658ba6cf3fc6420618d87bce3b62.png)


# **Найти OpenCommon**



Напишите скрипт Frida, чтобы просканировать все модули на наличие символов, содержащих "OpenCommon" или "DexFileLoader", и вывести их (включая имя модуля, имя символа, адрес)



find_symbols.js

```
// Скрипт Frida: поиск всех модулей, содержащих символы "OpenCommon" или "DexFileLoader"
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
            // Некоторые модули не могут быть перечислены, игнорируем
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


Вывод следующий:

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


Найден DexFileLoader::OpenCommon в libdexfile.so

```
[+] libdexfile.so -> _ZN3art13DexFileLoader10OpenCommonEPKhmS2_mRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEEPNS0_12VerifyResultE @ 0x7aac649c28
```
Таким образом, art/runtime/dex_file_loader.cc (реализация DexFileLoader::OpenCommon) в конечном итоге компилируется в libdexfile.so, а не в libart.so.



# **Распаковка через OpenCommon**



Используйте frida для перехвата функции DexFileLoader::OpenCommon в libdexfile.so и получения параметров base, size и location, чтобы дампить dex в каталог /sdcard/Android/data/pkgName/dump_dex:

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


Перечислите все процессы на текущем устройстве и отфильтруйте целевой процесс с помощью findstr

```
frida-ps -H 127.0.0.1:1234 | findstr cyrus
```


Выполните скрипт для начала дампа

```
frida -H 127.0.0.1:1234 -l dump_dex_from_open_common.js -f com.cyrus.example
```


Вывод следующий:

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


Можно увидеть, что dex уже дампирован на sdcard



![word/media/image9.png](https://gitee.com/cyrus-studio/images/raw/master/55c0144ce3bb1c5eb7ddff465a5cbfd1.png)


Используйте команду adb pull, чтобы одним разом скопировать весь каталог dump_dex с устройства на локальный компьютер:

```
adb pull /sdcard/Android/data/com.cyrus.example/dump_dex ./dumped_dex
```


Однако в выводе видно, что магия дампированных файлов - cdex001, cdex файлы нельзя напрямую декомпилировать с помощью инструментов декомпиляции dex



![word/media/image10.png](https://gitee.com/cyrus-studio/images/raw/master/c61540418336f940c463dac5f9533c76.png)


# **Запрет загрузки cdex**



Android 9 ввел CompactDex (.cdex, магия cdex001), это сжатая оптимизированная версия DEX, что делает невозможным декомпиляцию после дампа.



Оптимизированные файлы dex/cdex обычно хранятся в:

```
/data/app/package_name/oat/arm64/base.odex
/data/app/package_name/oat/arm64/base.vdex
```


Войдите в adb shell, найдите путь к oat файлам целевого приложения и удалите все oat файлы

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


Повторно выполните скрипт frida для дампа dex, из вывода видно, что магия дампированных файлов - dex 039 / dex 035 (магия стандартных Dex файлов), их можно напрямую декомпилировать с помощью jadx.

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


# **Декомпиляция dex с помощью jadx**



Используйте jadx для декомпиляции dex.



Проект jadx: [https://github.com/skylot/jadx](https://github.com/skylot/jadx)





![word/media/image11.png](https://gitee.com/cyrus-studio/images/raw/master/4816e881ee8000e5b1919e2bff08a6a0.png)


Каталог кеша по умолчанию для jadx

```
C:\Users\$USERNAME\AppData\Local\skylot\jadx\cache\projects
```


# **Распаковка через DexFile**



Найдите информацию о методе конструктора CompactDexFile:

```
[+] libdexfile.so -> _ZN3art14CompactDexFileC1EPKhmS2_mRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileENS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISG_EEEE @ 0x7aac6420e8
[+] libdexfile.so -> _ZN3art14CompactDexFileC2EPKhmS2_mRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileENS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISG_EEEE @ 0x7aac6420e8
```


Перехватите конструкторы CompactDexFile и StandardDexFile, чтобы получить base, size и location, и дампить dex.



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


Выполните скрипт:

```
frida -H 127.0.0.1:1234 -l dump_dex_from_dex_file.js -f com.cyrus.example
```


Вывод следующий:

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


Скопируйте файлы dex на локальный компьютер:

```
adb pull /sdcard/Android/data/com.cyrus.example/dump_dex ./dumped_dex
```


Используйте командную строку compact_dex_converter для преобразования файлов cdex (Compact Dex) в стандартные .dex файлы.

[https://github.com/anestisb/vdexExtractor#compact-dex-converter](https://github.com/anestisb/vdexExtractor#compact-dex-converter)



# **Распаковка через dex2oat**



Процесс dex2oat также можно использовать для распаковки.



При установке APK, если требуется компиляция ahead-of-time (AOT), installd вызывает dex2oat:



![word/media/image12.png](https://gitee.com/cyrus-studio/images/raw/master/608956255740c4fefcd613ee1b52900c.png)
[https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:frameworks/native/cmds/installd/dexopt.cpp;l=306](https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:frameworks/native/cmds/installd/dexopt.cpp;l=306)



Войдите в main() dex2oat.cc, в методе dex2oat::ReturnCode Setup() при регистрации dex в VerificationResults можно получить объект dex_file, это также хорошая точка для распаковки.

```
verification_results_->AddDexFile(dex_file);
```


![word/media/image13.png](https://gitee.com/cyrus-studio/images/raw/master/4a384bd1e48d829f9c6064b9d1299864.png)
[https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/dex2oat/dex2oat.cc;l=1685](https://cs.android.com/android/platform/superproject/+/android-10.0.0_r47:art/dex2oat/dex2oat.cc;l=1685)



# **Полный исходный код**



Открытый исходный код: [https://github.com/CYRUS-STUDIO/frida_dex_dump](https://github.com/CYRUS-STUDIO/frida_dex_dump)



Связанные статьи:

- _[Анализ процесса загрузки dex в среде ART и решение для дампа dex с помощью frida](https://bbs.kanxue.com/thread-277771.htm)_

- _[Прояснение: суть распаковки приложений Android и как быстро найти точки для распаковки под ART](https://bbs.kanxue.com/thread-254555.htm)_




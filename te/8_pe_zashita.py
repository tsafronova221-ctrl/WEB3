#!/usr/bin/env python3
"""
Скрипт для создания 200 теоретических вопросов по анализу PE файлов через hex
и защиты для 8 лабораторной работы.
"""

import sqlite3
import os
import shutil
import struct
from datetime import datetime

DB_PATH = 'instance/app.db'
LABS_DIR = 'instance/labs'
PROTECTIONS_DIR = 'instance/protections'

# 200 теоретических вопросов по PE файлам с ответами (число или слово)
# Ответы приведены в соответствие со спецификацией Microsoft PE/COFF
THEORY_QUESTIONS = [
# ==================== 1. DOS HEADER (Вопросы 1-21) ====================
("Какое значение сигнатуры (magic number) находится в DOS MZ заголовке по смещению 0x00?", "MZ"),
("Какие два ASCII-символа в шестнадцатеричном виде представляют байты сигнатуры DOS MZ?", "4D 5A"),
("По какому hex-смещению в PE-файле находится поле e_lfanew?", "0x3C"),
("Каков размер DOS MZ заголовка (IMAGE_DOS_HEADER) в байтах?", "64"),
("Какое поле по смещению 0x3C содержит файловое смещение NT заголовков?", "e_lfanew"),
("Сколько байт занимает поле e_magic в IMAGE_DOS_HEADER?", "2"),
("Какое hex-значение поля 'e_magic' для валидного PE-файла?", "0x5A4D"),
("Как называется поле в IMAGE_DOS_HEADER по смещению 0x02, хранящее количество байт на последней странице?", "e_cblp"),
("Какое поле в IMAGE_DOS_HEADER по смещению 0x04 хранит количество страниц?", "e_cp"),
("По какому смещению находится поле e_crlc (количество релокаций) в IMAGE_DOS_HEADER?", "0x06"),
("Каков размер в байтах поля e_cparhdr в IMAGE_DOS_HEADER?", "2"),
("Какое hex-смещение поля e_minalloc в IMAGE_DOS_HEADER?", "0x0A"),
("Какое поле по смещению 0x0C в IMAGE_DOS_HEADER хранит максимальное количество дополнительных параграфов?", "e_maxalloc"),
("Сколько зарезервированных полей типа WORD (e_res) существует в IMAGE_DOS_HEADER?", "4"),
("Какое смещение первого элемента массива e_res в IMAGE_DOS_HEADER?", "0x1C"),
("Каков общий размер в байтах зарезервированного массива e_res2 в IMAGE_DOS_HEADER?", "20"),
("Какое поле по смещению 0x3A предшествует e_lfanew в IMAGE_DOS_HEADER?", "e_ovno"),
("Каков десятичный размер DOS stub программы, которая обычно следует за IMAGE_DOS_HEADER?", "64"),
("Какое значение в e_lfanew означает, что NT заголовок начинается сразу после DOS заголовка?", "64"),
("Какое hex-представление ASCII символа 'M', используемого в первом байте сигнатуры MZ?", "0x4D"),
("Какое hex-представление ASCII символа 'Z', используемого во втором байте сигнатуры MZ?", "0x5A"),

# ==================== 2. NT HEADERS / СИГНАТУРА (Вопросы 22-42) ====================
("Какая PE-сигнатура в начале IMAGE_NT_HEADERS в hex?", "0x00004550"),
("Какие ASCII-символы представляет PE-сигнатура в начале NT заголовка?", "PE"),
("Какое 4-байтовое значение (magic) отмечает начало IMAGE_NT_HEADERS?", "50 45 00 00"),
("Как называется поле типа DWORD, содержащее PE-сигнатуру в IMAGE_NT_HEADERS?", "Signature"),
("Какая структура следует сразу за полем Signature в IMAGE_NT_HEADERS?", "IMAGE_FILE_HEADER"),
("Каков общий размер IMAGE_FILE_HEADER (COFF заголовка) в байтах?", "20"),
("Какое поле IMAGE_FILE_HEADER по смещению +0x00 идентифицирует целевую архитектуру CPU?", "Machine"),
("Какое hex-значение поля Machine для архитектуры x86 (Intel 386)?", "0x014C"),
("Какое hex-значение поля Machine для архитектуры AMD64/x86-64?", "0x8664"),
("Какое поле IMAGE_FILE_HEADER по смещению +0x02 хранит количество заголовков секций?", "NumberOfSections"),
("Какое поле IMAGE_FILE_HEADER по смещению +0x04 хранит временную метку создания файла?", "TimeDateStamp"),
("Какое поле IMAGE_FILE_HEADER по смещению +0x08 хранит смещение к таблице символов (устарело в PE)?", "PointerToSymbolTable"),
("Какое поле IMAGE_FILE_HEADER по смещению +0x0C хранит количество символов?", "NumberOfSymbols"),
("Какое поле IMAGE_FILE_HEADER по смещению +0x10 хранит размер Optional Header?", "SizeOfOptionalHeader"),
("Какое поле IMAGE_FILE_HEADER по смещению +0x12 содержит флаги характеристик образа?", "Characteristics"),
("Какое значение флага Characteristics (hex) указывает, что файл является исполняемым?", "0x0002"),
("Какое значение флага Characteristics (hex) указывает, что файл является DLL?", "0x2000"),
("Какое значение флага Characteristics (hex) указывает на 32-битную архитектуру?", "0x0100"),
("Какое hex-значение поля Machine для архитектуры ARM little-endian?", "0x01C0"),
("Какое hex-значение поля Machine для архитектуры IA-64 (Itanium)?", "0x0200"),
("Какой бит Characteristics указывает, что релокации не были удалены из файла?", "0x0001"),

# ==================== 3. OPTIONAL HEADER (Вопросы 43-81) ====================
("Какое значение magic number для Optional Header формата PE32 (32-бит)?", "0x010B"),
("Какое значение magic number для Optional Header формата PE32+ (64-бит)?", "0x020B"),
("Какое значение magic number для Optional Header ROM образа?", "0x0107"),
("Какое поле Optional Header по смещению +0x02 хранит основную версию компоновщика?", "MajorLinkerVersion"),
("Какое поле Optional Header по смещению +0x04 хранит общий размер секций кода?", "SizeOfCode"),
("Какое поле Optional Header хранит общий размер секций инициализированных данных?", "SizeOfInitializedData"),
("Какое поле Optional Header хранит размер неинициализированных данных (BSS)?", "SizeOfUninitializedData"),
("Какое поле Optional Header содержит RVA точки входа?", "AddressOfEntryPoint"),
("Какое поле Optional Header содержит RVA начала секции кода?", "BaseOfCode"),
("Какое поле Optional Header (только PE32) содержит RVA начала секции данных?", "BaseOfData"),
("Какое поле Optional Header хранит предпочтительный адрес загрузки образа?", "ImageBase"),
("Какой ImageBase по умолчанию для EXE файлов в hex?", "0x00400000"),
("Какой ImageBase по умолчанию для DLL файлов в hex?", "0x10000000"),
("Какое поле Optional Header определяет выравнивание секций в памяти?", "SectionAlignment"),
("Какое поле Optional Header определяет выравнивание секций в файле?", "FileAlignment"),
("Какое значение FileAlignment по умолчанию в байтах?", "512"),
("Какое поле Optional Header хранит требуемую основную версию ОС?", "MajorOperatingSystemVersion"),
("Какое поле Optional Header хранит номер основной версии образа?", "MajorImageVersion"),
("Какое поле Optional Header хранит минимальную требуемую основную версию подсистемы?", "MajorSubsystemVersion"),
("Какое поле Optional Header должно быть установлено в ноль: Win32VersionValue?", "Win32VersionValue"),
("Какое поле Optional Header хранит общий размер образа в памяти?", "SizeOfImage"),
("Какое поле Optional Header хранит суммарный размер заголовков (DOS+PE+секции)?", "SizeOfHeaders"),
("Какое поле Optional Header хранит контрольную сумму образа?", "CheckSum"),
("Какое поле Optional Header идентифицирует подсистему (GUI, CUI и т.д.)?", "Subsystem"),
("Какое значение Subsystem (десятичное) означает приложение Windows GUI?", "2"),
("Какое значение Subsystem (десятичное) означает консольное приложение Windows CUI?", "3"),
("Какое поле Optional Header хранит флаги характеристик, специфичные для DLL?", "DllCharacteristics"),
("Какой флаг DllCharacteristics (hex) включает ASLR (динамический базовый адрес)?", "0x0040"),
("Какой флаг DllCharacteristics (hex) включает DEP (NX совместимость)?", "0x0100"),
("Какой флаг DllCharacteristics (hex) указывает на отсутствие SEH?", "0x0400"),
("Какое поле Optional Header хранит размер резервируемого стека?", "SizeOfStackReserve"),
("Какое поле Optional Header хранит размер изначально выделяемого стека?", "SizeOfStackCommit"),
("Какое поле Optional Header хранит размер резервируемой кучи?", "SizeOfHeapReserve"),
("Какое поле Optional Header зарезервировано и должно быть равно нулю: LoaderFlags?", "LoaderFlags"),
("Какое поле Optional Header содержит количество записей в Data Directory?", "NumberOfRvaAndSizes"),
("Какое стандартное значение NumberOfRvaAndSizes?", "16"),
("Каков размер IMAGE_OPTIONAL_HEADER32 без Data Directory в байтах?", "96"),
("Каков размер IMAGE_OPTIONAL_HEADER64 без Data Directory в байтах?", "112"),
("Каков размер каждой записи IMAGE_DATA_DIRECTORY в байтах?", "8"),

# ==================== 4. SECTION HEADER (Вопросы 82-109) ====================
("Каков размер IMAGE_SECTION_HEADER в байтах?", "40"),
("Каков размер поля Name в IMAGE_SECTION_HEADER в байтах?", "8"),
("Какое поле IMAGE_SECTION_HEADER хранит виртуальный размер секции?", "VirtualSize"),
("Какое поле IMAGE_SECTION_HEADER хранит RVA, по которому секция отображается в память?", "VirtualAddress"),
("Какое поле IMAGE_SECTION_HEADER хранит размер данных секции в файле?", "SizeOfRawData"),
("Какое поле IMAGE_SECTION_HEADER хранит файловое смещение данных секции?", "PointerToRawData"),
("Какое поле IMAGE_SECTION_HEADER хранит файловое смещение релокаций?", "PointerToRelocations"),
("Какое поле IMAGE_SECTION_HEADER хранит файловое смещение записей номеров строк?", "PointerToLinenumbers"),
("Какое поле IMAGE_SECTION_HEADER хранит количество записей релокаций?", "NumberOfRelocations"),
("Какое поле IMAGE_SECTION_HEADER хранит флаги характеристик секции?", "Characteristics"),
("Какой флаг Characteristics секции (hex) означает, что секция содержит исполняемый код?", "0x20000000"),
("Какой флаг Characteristics секции (hex) означает, что секция доступна для чтения?", "0x40000000"),
("Какой флаг Characteristics секции (hex) означает, что секция доступна для записи?", "0x80000000"),
("Какой флаг Characteristics секции (hex) означает, что секция содержит инициализированные данные?", "0x00000040"),
("Какой флаг Characteristics секции (hex) означает, что секция содержит неинициализированные данные?", "0x00000080"),
("Какой флаг Characteristics секции (hex) означает, что секция может быть выгружена?", "0x02000000"),
("Какой флаг Characteristics секции (hex) означает, что секция не кэшируется?", "0x04000000"),
("Какой флаг Characteristics секции (hex) означает, что секция не выгружается в файл подкачки?", "0x08000000"),
("Какой флаг Characteristics секции (hex) означает, что секция разделяемая?", "0x10000000"),
("Какое типичное имя секции кода в PE файлах?", ".text"),
("Какое типичное имя секции данных только для чтения?", ".rdata"),
("Какое типичное имя секции инициализированных данных?", ".data"),
("Какое типичное имя секции BSS (неинициализированные данные)?", ".bss"),
("Какое типичное имя секции ресурсов?", ".rsrc"),
("Какое типичное имя секции релокаций?", ".reloc"),
("Какое типичное имя секции экспорта?", ".edata"),
("Какое типичное имя секции импорта?", ".idata"),
("Какое типичное имя секции TLS?", ".tls"),

# ==================== 5. DATA DIRECTORIES (Вопросы 110-129) ====================
("Какой индекс (0-based) у Export Directory в массиве Data Directory?", "0"),
("Какой индекс (0-based) у Import Directory в массиве Data Directory?", "1"),
("Какой индекс (0-based) у Resource Directory в массиве Data Directory?", "2"),
("Какой индекс (0-based) у Exception Directory в массиве Data Directory?", "3"),
("Какой индекс (0-based) у Certificate/Security Directory в массиве Data Directory?", "4"),
("Какой индекс (0-based) у Base Relocation Table в массиве Data Directory?", "5"),
("Какой индекс (0-based) у Debug Directory в массиве Data Directory?", "6"),
("Какой индекс (0-based) у Architecture-specific Data directory (зарезервировано)?", "7"),
("Какой индекс (0-based) у Global Pointer Register directory?", "8"),
("Какой индекс (0-based) у TLS Directory в массиве Data Directory?", "9"),
("Какой индекс (0-based) у Load Configuration Directory?", "10"),
("Какой индекс (0-based) у Bound Import Directory?", "11"),
("Какой индекс (0-based) у Import Address Table (IAT) directory?", "12"),
("Какой индекс (0-based) у Delay Import Directory?", "13"),
("Какой индекс (0-based) у COM+ Runtime Header (CLR) Directory?", "14"),
("Какой индекс зарезервирован и должен быть равен нулю в Data Directory?", "15"),
("Какие два поля содержит каждая запись IMAGE_DATA_DIRECTORY?", "VirtualAddress, Size"),
("Сколько байт занимает поле VirtualAddress в IMAGE_DATA_DIRECTORY?", "4"),
("Сколько байт занимает поле Size в IMAGE_DATA_DIRECTORY?", "4"),
("Каков общий размер в байтах всех 16 записей IMAGE_DATA_DIRECTORY?", "128"),

# ==================== 6. IMPORT TABLE (Вопросы 130-149) ====================
("Какая структура описывает каждую импортируемую DLL в таблице импорта?", "IMAGE_IMPORT_DESCRIPTOR"),
("Каков размер IMAGE_IMPORT_DESCRIPTOR в байтах?", "20"),
("Какое поле в IMAGE_IMPORT_DESCRIPTOR является RVA Import Lookup Table (ILT)?", "OriginalFirstThunk"),
("Какое поле в IMAGE_IMPORT_DESCRIPTOR хранит временную метку DLL?", "TimeDateStamp"),
("Какое поле в IMAGE_IMPORT_DESCRIPTOR хранит ForwarderChain?", "ForwarderChain"),
("Какое поле в IMAGE_IMPORT_DESCRIPTOR является RVA строки имени DLL?", "Name"),
("Какое поле в IMAGE_IMPORT_DESCRIPTOR является RVA Import Address Table?", "FirstThunk"),
("Какое значение в TimeDateStamp указывает, что импорт привязан (bound)?", "0xFFFFFFFF"),
("Какой старший бит (31 или 63) устанавливается в записи ILT для указания импорта по ординалу?", "1"),
("Какая структура содержит hint и имя для именованного импорта?", "IMAGE_IMPORT_BY_NAME"),
("Какое поле в IMAGE_IMPORT_BY_NAME хранит hint (индекс в таблице имен экспорта)?", "Hint"),
("Какое поле в IMAGE_IMPORT_BY_NAME хранит null-терминированную строку имени функции?", "Name"),
("Чем заканчивается таблица импорта (Import Directory Table)?", "null entry"),
("Каков размер записи thunk (ILT/IAT) в байтах для PE32?", "4"),
("Каков размер записи thunk (ILT/IAT) в байтах для PE32+?", "8"),
("Что содержит запись IAT для разрешенного импорта после загрузки?", "function address"),
("Какой индекс Data Directory указывает на IAT напрямую (отдельно от import dir)?", "12"),
("Какая маска для извлечения ординала из записи ILT в PE32 при установленном старшем бите?", "0x0000FFFF"),
("Какая маска для извлечения ординала из записи ILT в PE32+ при установленном старшем бите?", "0x000FFFF"),
("Какое значение bound import означает, что импорт не привязан?", "0"),

# ==================== 7. EXPORT TABLE (Вопросы 150-169) ====================
("Какая структура определяет Export Directory в PE файле?", "IMAGE_EXPORT_DIRECTORY"),
("Каков размер IMAGE_EXPORT_DIRECTORY в байтах?", "40"),
("Какое поле в IMAGE_EXPORT_DIRECTORY хранит флаги (должно быть 0)?", "Characteristics"),
("Какое поле IMAGE_EXPORT_DIRECTORY хранит временную метку DLL?", "TimeDateStamp"),
("Какое поле хранит основную версию DLL в IMAGE_EXPORT_DIRECTORY?", "MajorVersion"),
("Какое поле IMAGE_EXPORT_DIRECTORY является RVA строки имени модуля?", "Name"),
("Какое поле в IMAGE_EXPORT_DIRECTORY хранит начальную базу ординалов?", "Base"),
("Какое поле IMAGE_EXPORT_DIRECTORY хранит общее количество экспортируемых функций?", "NumberOfFunctions"),
("Какое поле хранит количество именованных экспортов в IMAGE_EXPORT_DIRECTORY?", "NumberOfNames"),
("Какое поле IMAGE_EXPORT_DIRECTORY является RVA Export Address Table (EAT)?", "AddressOfFunctions"),
("Какое поле является RVA таблицы указателей на имена в IMAGE_EXPORT_DIRECTORY?", "AddressOfNames"),
("Какое поле IMAGE_EXPORT_DIRECTORY является RVA таблицы ординалов?", "AddressOfNameOrdinals"),
("Как идентифицируется перенаправленный (forwarded) экспорт в EAT?", "RVA points inside .edata"),
("Каков размер каждой записи в Export Address Table в байтах?", "4"),
("Каков размер каждой записи в таблице указателей на имена в байтах?", "4"),
("Каков размер каждой записи в таблице ординалов в байтах?", "2"),
("В какой таблице сначала выполняется бинарный поиск для разрешения экспорта по имени?", "name pointer table"),
("Каково соотношение индекса ординала и имени: ordinal = name_ordinal + ?", "Base"),
("Какое значение в поле Characteristics структуры IMAGE_EXPORT_DIRECTORY должно быть всегда?", "0"),
("На что указывает запись EAT, которая ссылается внутрь секции экспорта?", "forwarder string"),

# ==================== 8. BASE RELOCATIONS (Вопросы 170-189) ====================
("Какая структура заголовка описывает каждый блок релокаций?", "IMAGE_BASE_RELOCATION"),
("Какое поле в IMAGE_BASE_RELOCATION хранит RVA страницы для блока?", "VirtualAddress"),
("Какое поле в IMAGE_BASE_RELOCATION хранит общий размер блока в байтах?", "SizeOfBlock"),
("Каков размер заголовка IMAGE_BASE_RELOCATION в байтах?", "8"),
("Каков размер каждой записи релокации (WORD) после заголовка в байтах?", "2"),
("Сколько бит в каждой WORD-записи релокации занимает тип?", "4"),
("Сколько бит в каждой WORD-записи релокации занимает смещение внутри страницы?", "12"),
("Какой тип релокации (десятичный) используется как заполнитель/no-op?", "0"),
("Какой тип релокации (десятичный) указывает на 32-битную релокацию (HIGHLOW)?", "3"),
("Какой тип релокации (десятичный) указывает на 64-битную релокацию (DIR64)?", "10"),
("Какой тип релокации (десятичный) корректирует старшие 16 бит (HIGH)?", "1"),
("Какой тип релокации (десятичный) корректирует младшие 16 бит (LOW)?", "2"),
("Какой тип релокации (десятичный) используется для HIGHADJ (старшие с коррекцией)?", "4"),
("Каков размер страницы, используемый для блоков релокаций, в байтах?", "4096"),
("Какое значение в SizeOfBlock завершает таблицу релокаций?", "0"),
("Дельта, применяемая при релокации = фактический ImageBase минус что?", "preferred ImageBase"),
("Какой флаг Characteristics в IMAGE_FILE_HEADER означает, что релокации были удалены?", "0x0001"),
("Какой флаг DllCharacteristics (hex) означает, что образ поддерживает динамический базовый адрес (ASLR)?", "0x0040"),
("В какой секции обычно хранятся данные базовых релокаций?", ".reloc"),
("Как вычислить количество записей релокаций в блоке, зная SizeOfBlock?", "(SizeOfBlock - 8) / 2"),

# ==================== 9. TLS DIRECTORY (Вопросы 190-209) ====================
("Какая структура определяет TLS Directory?", "IMAGE_TLS_DIRECTORY"),
("Какое поле IMAGE_TLS_DIRECTORY хранит VA начала сырых данных TLS (32-бит)?", "StartAddressOfRawData"),
("Какое поле IMAGE_TLS_DIRECTORY хранит VA конца сырых данных TLS?", "EndAddressOfRawData"),
("Какое поле IMAGE_TLS_DIRECTORY хранит VA переменной индекса TLS?", "AddressOfIndex"),
("Какое поле IMAGE_TLS_DIRECTORY хранит VA массива TLS callback-функций?", "AddressOfCallBacks"),
("Какое поле IMAGE_TLS_DIRECTORY хранит размер zero-fill для TLS?", "SizeOfZeroFill"),
("Какое поле IMAGE_TLS_DIRECTORY хранит выравнивание и характеристики?", "Characteristics"),
("Каков размер IMAGE_TLS_DIRECTORY32 в байтах?", "24"),
("Каков размер IMAGE_TLS_DIRECTORY64 в байтах?", "40"),
("Какой индекс Data Directory для TLS?", "9"),
("TLS callbacks вызываются перед какой функцией при запуске процесса?", "entry point"),
("Какое значение завершает массив TLS callback-функций?", "0"),
("Адреса в TLS Directory используют VA или RVA?", "VA"),
("В какой секции обычно содержатся данные TLS?", ".tls"),
("По какой причине флага TLS callbacks могут не выполняться в 64-бит? Отсутствие какой функции?", "ASLR"),
("Какой бит DllCharacteristics должен быть сброшен, чтобы TLS callbacks корректно работали при ASLR?", "0x0040"),
("VA индекса TLS указывает на DWORD, в который загрузчик записывает что?", "TLS slot index"),
("Какие биты выравнивания в поле Characteristics занимают биты 20-23?", "ALIGN"),
("Для PE32+ каков размер поля StartAddressOfRawData в байтах?", "8"),
("TLS callbacks имеют прототип, схожий с какой известной callback-функцией DLL?", "DllMain"),
]

def create_theory_lab():
    """Создает лабораторную работу с 200 теоретическими вопросами"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Находим ID группы КС-22-03 (или создаем если нет)
    c.execute("SELECT id FROM groups WHERE name = 'КС-22-03'")
    group = c.fetchone()
    if not group:
        c.execute("INSERT INTO groups (name, size) VALUES (?, ?)", ('КС-22-03', 25))
        conn.commit()
        c.execute("SELECT id FROM groups WHERE name = 'КС-22-03'")
        group = c.fetchone()
    group_id = group[0]

    # Создаем новую лабораторную работу для теории
    lab_title = "Теория_PE_hex_200вопросов"
    c.execute("SELECT id FROM labs WHERE title = ?", (lab_title,))
    existing = c.fetchone()

    if existing:
        lab_id = existing[0]
        # Удаляем старые вопросы
        c.execute("DELETE FROM file_question_answers WHERE question_id IN (SELECT id FROM questions WHERE lab_id = ?)", (lab_id,))
        c.execute("DELETE FROM questions WHERE lab_id = ?", (lab_id,))
        c.execute("DELETE FROM lab_files WHERE lab_id = ?", (lab_id,))
        c.execute("DELETE FROM lab_passwords WHERE lab_id = ?", (lab_id,))
    else:
        # Создаем новую ЛР
        from datetime import datetime
        start_at = datetime(2025, 2, 1, 0, 0, 0)
        deadline_at = datetime(2025, 12, 31, 23, 59, 59)

        c.execute("""INSERT INTO labs (title, code, start_at, deadline_at, description, is_test, questions_count, test_duration)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                  (lab_title, f"LAB-{int(datetime.now().timestamp())}", start_at, deadline_at, "", 1, 50, 90))
        conn.commit()
        lab_id = c.lastrowid

    # Привязываем группу к ЛР
    c.execute("DELETE FROM lab_groups WHERE lab_id = ?", (lab_id,))
    c.execute("INSERT INTO lab_groups (lab_id, group_id) VALUES (?, ?)", (lab_id, group_id))

    # Создаем один фиктивный файл (так как система требует файлы)
    files_dir = os.path.join(LABS_DIR, str(lab_id))
    os.makedirs(files_dir, exist_ok=True)

    # Создаем простой PE файл (заглушку)
    pe_stub = create_minimal_pe()
    pe_path = os.path.join(files_dir, "theory_reference.exe")
    with open(pe_path, "wb") as f:
        f.write(pe_stub)

    c.execute("INSERT INTO lab_files (lab_id, file_path) VALUES (?, ?)", (lab_id, pe_path))
    conn.commit()
    file_id = c.lastrowid

    # Добавляем 200 вопросов
    for i, (question_text, answer) in enumerate(THEORY_QUESTIONS, 1):
        c.execute("INSERT INTO questions (lab_id, text) VALUES (?, ?)", (lab_id, question_text))
        question_id = c.lastrowid

        # Добавляем ответ для файла
        c.execute("INSERT INTO file_question_answers (lab_file_id, question_id, correct_answer) VALUES (?, ?, ?)",
                  (file_id, question_id, answer))

    conn.commit()
    conn.close()

    print(f"Создана лабораторная работа '{lab_title}' с ID={lab_id}")
    print(f"Добавлено {len(THEORY_QUESTIONS)} вопросов")
    return lab_id


def create_minimal_pe():
    """Создает минимальный PE файл для справки"""
    # DOS Header (64 байта)
    dos_header = bytearray(64)
    dos_header[0:2] = b'MZ'  # e_magic
    struct.pack_into('<H', dos_header, 2, 0x5A)  # e_cp
    struct.pack_into('<H', dos_header, 4, 0x3)   # e_cblp
    struct.pack_into('<H', dos_header, 8, 0x4)   # e_cparhdr
    struct.pack_into('<H', dos_header, 24, 0xFFFF)  # e_maxalloc
    struct.pack_into('<H', dos_header, 40, 0xB8)  # e_ip (начало кода)
    struct.pack_into('<I', dos_header, 60, 64)   # e_lfanew - PE header начинается с 64

    # DOS Stub (простой код выхода)
    dos_stub = bytes([
        0xBA, 0x10, 0x00, 0x00, 0x00,  # mov dx, 10h
        0xCD, 0x21,                     # int 21h
        0xB8, 0x01, 0x4C, 0x00,         # mov ax, 4C01h
        0xCD, 0x21,                     # int 21h
    ])

    # PE Signature
    pe_sig = b'PE\x00\x00'

    # COFF Header (20 bytes)
    coff_header = bytearray(20)
    struct.pack_into('<H', coff_header, 0, 0x14C)    # Machine (x86)
    struct.pack_into('<H', coff_header, 2, 3)        # NumberOfSections
    struct.pack_into('<I', coff_header, 4, 0x5F000000)  # TimeDateStamp
    struct.pack_into('<I', coff_header, 8, 0)        # PointerToSymbolTable
    struct.pack_into('<I', coff_header, 12, 0)       # NumberOfSymbols
    struct.pack_into('<H', coff_header, 16, 0xE0)    # SizeOfOptionalHeader (PE32)
    struct.pack_into('<H', coff_header, 18, 0x102)   # Characteristics (EXECUTABLE_IMAGE | 32BIT_MACHINE)

    # Optional Header PE32 (224 bytes = 0xE0)
    opt_header = bytearray(224)
    struct.pack_into('<H', opt_header, 0, 0x10B)     # Magic (PE32)
    opt_header[2] = 14                                # MajorLinkerVersion
    opt_header[3] = 0                                 # MinorLinkerVersion
    struct.pack_into('<I', opt_header, 4, 0x1000)    # SizeOfCode
    struct.pack_into('<I', opt_header, 8, 0x1000)    # SizeOfInitializedData
    struct.pack_into('<I', opt_header, 12, 0)        # SizeOfUninitializedData
    struct.pack_into('<I', opt_header, 16, 0x1000)   # AddressOfEntryPoint (RVA)
    struct.pack_into('<I', opt_header, 20, 0x1000)   # BaseOfCode
    struct.pack_into('<I', opt_header, 24, 0x2000)   # BaseOfData
    struct.pack_into('<I', opt_header, 28, 0x400000) # ImageBase
    struct.pack_into('<I', opt_header, 32, 0x1000)   # SectionAlignment
    struct.pack_into('<I', opt_header, 36, 0x200)    # FileAlignment
    struct.pack_into('<H', opt_header, 40, 6)        # MajorOperatingSystemVersion
    struct.pack_into('<H', opt_header, 42, 0)        # MinorOperatingSystemVersion
    struct.pack_into('<H', opt_header, 44, 0)        # MajorImageVersion
    struct.pack_into('<H', opt_header, 46, 0)        # MinorImageVersion
    struct.pack_into('<H', opt_header, 48, 6)        # MajorSubsystemVersion
    struct.pack_into('<H', opt_header, 50, 0)        # MinorSubsystemVersion
    struct.pack_into('<I', opt_header, 52, 0)        # Win32VersionValue
    struct.pack_into('<I', opt_header, 56, 0x3000)   # SizeOfImage
    struct.pack_into('<I', opt_header, 60, 0x200)    # SizeOfHeaders
    struct.pack_into('<I', opt_header, 64, 0)        # CheckSum
    struct.pack_into('<H', opt_header, 68, 3)        # Subsystem (Console)
    struct.pack_into('<H', opt_header, 70, 0)        # DllCharacteristics
    struct.pack_into('<I', opt_header, 72, 0x100000) # SizeOfStackReserve
    struct.pack_into('<I', opt_header, 76, 0x1000)   # SizeOfStackCommit
    struct.pack_into('<I', opt_header, 80, 0x100000) # SizeOfHeapReserve
    struct.pack_into('<I', opt_header, 84, 0x1000)   # SizeOfHeapCommit
    struct.pack_into('<I', opt_header, 88, 0)        # LoaderFlags
    struct.pack_into('<I', opt_header, 92, 16)       # NumberOfRvaAndSizes

    # Data Directory (16 entries * 8 = 128 bytes) - все нули
    data_dir = bytearray(128)

    # Section Headers (3 секции * 40 = 120 bytes)
    sections = bytearray(120)

    # .text секция
    sections[0:8] = b'.text\x00\x00\x00'
    struct.pack_into('<I', sections, 8, 0x1000)     # VirtualSize
    struct.pack_into('<I', sections, 12, 0x1000)    # VirtualAddress
    struct.pack_into('<I', sections, 16, 0x200)     # SizeOfRawData
    struct.pack_into('<I', sections, 20, 0x200)     # PointerToRawData
    struct.pack_into('<I', sections, 36, 0x60000020) # Characteristics (CODE | EXECUTE | READ)

    # .data секция
    sections[40:48] = b'.data\x00\x00\x00'
    struct.pack_into('<I', sections, 48, 0x1000)    # VirtualSize
    struct.pack_into('<I', sections, 52, 0x2000)    # VirtualAddress
    struct.pack_into('<I', sections, 56, 0x200)     # SizeOfRawData
    struct.pack_into('<I', sections, 60, 0x400)     # PointerToRawData
    struct.pack_into('<I', sections, 76, 0xC0000040) # Characteristics (DATA | READ | WRITE)

    # .rsrc секция
    sections[80:88] = b'.rsrc\x00\x00\x00'
    struct.pack_into('<I', sections, 88, 0x1000)    # VirtualSize
    struct.pack_into('<I', sections, 92, 0x3000)    # VirtualAddress
    struct.pack_into('<I', sections, 96, 0x200)     # SizeOfRawData
    struct.pack_into('<I', sections, 100, 0x600)    # PointerToRawData
    struct.pack_into('<I', sections, 116, 0x40000040) # Characteristics (DATA | READ)

    # Собираем всё вместе
    pe_file = bytes(dos_header) + dos_stub + pe_sig + bytes(coff_header) + bytes(opt_header) + bytes(data_dir) + bytes(sections)

    # Дополняем до нужного размера (выравнивание по FileAlignment = 0x200)
    while len(pe_file) % 0x200 != 0:
        pe_file += b'\x00'

    pe_file += bytes(0x1000)  # .text секция
    pe_file += bytes(0x1000)  # .data секция
    pe_file += bytes(0x1000)  # .rsrc секция

    return pe_file


def create_protection_for_lab8():
    """Создает защиту для 8 лабораторной работы (PE анализ)"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Находим все ЛР с номером 8
    c.execute("SELECT id, title FROM labs WHERE title LIKE '%8%' OR title LIKE '%PE%'")
    lab8_list = c.fetchall()

    print(f"Найдено лабораторных работ связанных с 8 лабой: {len(lab8_list)}")

    for lab_id, lab_title in lab8_list:
        print(f"  Обработка ЛР #{lab_id}: {lab_title}")

        # Проверяем есть ли уже пароли
        c.execute("SELECT COUNT(*) FROM lab_passwords WHERE lab_id = ?", (lab_id,))
        count = c.fetchone()[0]

        if count == 0:
            # Генерируем пароли для каждого файла
            import string
            import secrets

            c.execute("SELECT id FROM lab_files WHERE lab_id = ?", (lab_id,))
            files = c.fetchall()

            for (file_id,) in files:
                password = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(10))
                c.execute("INSERT INTO lab_passwords (lab_id, file_id, password) VALUES (?, ?, ?)",
                          (lab_id, file_id, password))

            conn.commit()
            print(f"    Сгенерированы пароли для {len(files)} файлов")
        else:
            print(f"    Пароли уже существуют ({count} шт)")

    conn.close()
    print("Защита для 8 лабы создана/обновлена")


if __name__ == "__main__":
    print("=== Создание 200 теоретических вопросов по PE ===")
    create_theory_lab()

    print("\n=== Создание защиты для 8 лабораторной работы ===")
    create_protection_for_lab8()

    print("\n=== Готово! ===")
# asnut: Утиліта для шифрування та стеганографії

`asnut` - це консольна утиліта, написана на Rust, призначена для шифрування/дешифрування файлів та каталогів, генерації ключів шифрування, а також для приховування файлів у зображеннях (стеганографія) та їх вилучення.

## Можливості

* **Шифрування та Дешифрування:**
    * Підтримка окремих файлів та цілих каталогів.
    * Обробка великих файлів (>100MB) блоками для ефективного використання пам'яті.
* **Алгоритми шифрування:**
    * AES-128-GCM
    * AES-256-GCM (за замовчуванням)
    * ChaCha20-Poly1305
    * (Усі алгоритми використовують AEAD для забезпечення конфіденційності, цілісності та автентичності даних)
* **Управління ключами:**
    * Генерація нових ключів для обраних алгоритмів.
    * Використання пароля для генерації ключа (з використанням PBKDF2-HMAC-SHA256 та солі), який може бути вбудований у вихідний файл.
    * Збереження згенерованих ключів у файл (у відкритому шістнадцятковому форматі або захищеному паролем).
    * Використання ключів з існуючих файлів (відкритих або захищених паролем).
* **Стеганографія (для PNG зображень):**
    * Приховування файлу всередині зображення-контейнера (секретний файл попередньо шифрується).
    * Вилучення прихованого файлу з зображення-контейнера (з подальшим дешифруванням).
* **Безпека:**
    * Використання криптографічно стійкого генератора випадкових чисел для ключів та nonce.
    * Захист паролів у пам'яті за допомогою крейту `secrecy`.
    * Приховування введення пароля в консолі.
* **Інтерфейс:**
    * Командний рядок з детальними опціями.
    * Тихий (`-s`) та детальний (`-v`) режими виводу.

## Встановлення та Запуск

1.  **Завантаження:**
    * Перейдіть на сторінку [**Releases**](https://github.com/dom-300/asnut/releases) цього репозиторію.
    * Завантажте останню версію виконуваного файлу для вашої операційної системи:
       * Для Linux: `asnut` https://github.com/dom-300/asnut/releases/download/v0.1.0/asnut 
       * Для Windows: `asnut.exe` https://github.com/dom-300/asnut/releases/download/v0.1.0/asnut.exe
       * (Опціонально) Перевірте контрольну суму завантаженого файлу, якщо вона надана.

2.  **Підготовка до запуску:**
    * **Linux:**
        Відкрийте термінал у каталозі, куди ви завантажили файл, та надайте йому права на виконання:
        ```bash
        chmod +x ./asnut
        ```
        Тепер ви можете запускати утиліту так: `./asnut [аргументи]`
    * **Windows:**
        Аналогічно як і у системі Linux тільки використовуючи Powershell

3.  **(Рекомендовано) Додавання до PATH:**
    Для зручного запуску утиліти з будь-якого каталогу, просто ввівши `asnut`, додайте каталог, де знаходиться виконуваний файл, до системної змінної `PATH`.
    * **Linux:** Скопіюйте файл у `/usr/local/bin` або `~/.local/bin`, або додайте шлях до вашого каталогу в `~/.bashrc`, `~/.zshrc` тощо.
    * **Windows:** Дотримуйтесь інструкцій для додавання шляху до змінної середовища `Path` через властивості системи.

## Використання

Загальний формат команди:
```bash
asnut -a <ДІЯ> [АРГУМЕНТИ ДІЇ] [ЗАГАЛЬНІ ОПЦІЇ]
Щоб отримати повний список доступних дій та опцій, виконайте:

Bash

asnut --help
Основні дії (-a, --action)
encrypt: Шифрування файлу або каталогу.

-f <файл> або -d <каталог>: Ціль для шифрування.
Ключові опції: -k <файл_ключа>, -p (використати пароль), -S <зберегти_ключ_у_файл>.
Алгоритм: -l <алгоритм> (aes-256, aes-128, chacha20).
Вивід: -o <вихідний_файл/каталог>.
decrypt: Дешифрування файлу або каталогу.

-f <файл> або -d <каталог>: Ціль для дешифрування.
Ключові опції: -k <файл_ключа>, -p (використати пароль).
Алгоритм: -l <алгоритм> (зазвичай визначається з файлу).
Вивід: -o <вихідний_файл/каталог>.
gen-key: Генерація нового ключа шифрування.

Алгоритм: -l <алгоритм>.
Вивід: -o <файл_для_ключа> (якщо не вказано, ключ виводиться в консоль).
Захист паролем: -p (якщо використовується з -o).
steg-hide: Приховати секретний файл у зображенні PNG.

-f <секретний_файл>: Файл, який потрібно приховати.
-c <зображення_контейнер.png>: Зображення, в яке буде сховано файл (файл буде змінено!).
Ключові опції для шифрування секрету: -k, -p, -S, -l.
steg-extract: Вилучити секретний файл зі стего-зображення.

-f <стего_зображення.png>: Зображення, з якого вилучаються дані.
-o <вихідний_файл_секрету>: Файл для збереження вилученого секрету.
Ключові опції для дешифрування секрету: -k, -p, -l.
Загальні опції
-v, --verbose: Детальний вивід інформації.
-s, --silent: Тихий режим (мінімум повідомлень).
Приклади
Згенерувати ключ AES-256 та зберегти його у файл mykey.key, захистивши паролем:

Bash

asnut -a gen-key -l aes-256 -o mykey.key -p
Зашифрувати файл document.txt за допомогою пароля (ключ буде вбудовано у вихідний файл):

Bash

asnut -a encrypt -f document.txt -p
Дешифрувати файл document.txt.enc за допомогою ключа з файлу mykey.key (який може бути захищений паролем – програма запитає його, якщо потрібно):

Bash

asnut -a decrypt -f document.txt.enc -k mykey.key
Приховати secret.doc у photo.png, використовуючи для шифрування секрету ключ mykey.key:

Bash

asnut -a steg-hide -f secret.doc -c photo.png -k mykey.key
Вилучити секрет з photo.png у retrieved_secret.doc, використовуючи ключ mykey.key:

Bash

asnut -a steg-extract -f photo.png -o retrieved_secret.doc -k mykey.key
Збірка з вихідного коду
Якщо ви хочете зібрати утиліту самостійно:

Встановіть Rust.
Клонуйте цей репозиторій:
Bash

git clone [https://github.com/dom-300/asnut.git](https://github.com/dom-300/asnut.git)
cd asnut
Зберіть проєкт:
Bash

cargo build --release
Виконуваний файл буде знаходитися в каталозі target/release/.
Ліцензія
Цей проєкт ліцензовано на умовах ліцензії  - дивіться файл LICENSE для деталей.
(Наприклад: MIT License)

Внесок та Зворотний зв'язок
Якщо у вас є пропозиції, ви знайшли помилку або хочете зробити свій внесок, будь ласка, створюйте "Issue" або "Pull Request" у цьому репозиторії.

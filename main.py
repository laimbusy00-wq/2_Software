import itertools
import hashlib
import time
import argparse
import math
from multiprocessing import Process, Manager, Value
import bcrypt
from argon2 import PasswordHasher

ph = PasswordHasher()

BUILTIN_HASHES = [
    # SHA-1
    ("sha1", "7c4a8d09ca3762af61e59520943dc26494f8941b", "SHA-1 легкий"),
    ("sha1", "d0be2dc421be4fcd0172e5afceea3970e2f3d940", "SHA-1 средний"),
    ("sha1", "666846867fc5e0a46a7afc53eb8060967862f333", "SHA-1 сложный"),
    ("sha1", "6e157c5da4410b7e9de85f5c93026b9176e69064", "SHA-1 очень сложный"),
    # MD5
    ("md5", "e10adc3949ba59abbe56e057f20f883e", "MD5 легкий"),
    ("md5", "1f3870be274f6c49b3e31a0c6728957f", "MD5 средний"),
    ("md5", "77892341aa9dc66e97f5c248782b5d92", "MD5 сложный"),
    ("md5", "686e697538050e4664636337cc3b834f", "MD5 очень сложный"),
    # bcrypt
    ("bcrypt", "$2a$10$z4u9ZkvopUiiytaNX7wfGedy9Lu2ywUxwYpbsAR5YBrAuUs3YGXdi", "bcrypt легкий"),
    ("bcrypt", "$2a$10$26GB/T2/6aTsMkTjCgqm/.JP8SUjr32Bhfn9m9smtDiIwM4QIt2ze", "bcrypt средний"),
    ("bcrypt", "$2a$10$Q9M0vLLrE4/nu/9JEMXFTewB3Yr9uMdIEZ1Sgdk1NQTjHwLN0asfi", "bcrypt сложный"),
    ("bcrypt", "$2a$10$yZBadi8Szw0nItV2g96P6eqctI2kbG/.mb0uD/ID9tlof0zpJLLL2", "bcrypt очень сложный"),
    # Argon2
    ("argon2", "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$PUF5UxxoUY++mMekkQwFurL0ZsTtB7lelO23zcyZQ0c", "Argon2 легкий"),
    ("argon2", "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$HYQwRUw9VcfkvqkUQ5ppyYPom6f/ro3ZCXYznhrYZw4", "Argon2 средний"),
    ("argon2", "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$9asGA7Xv3vQBz7Yyh4/Ntw0GQgOg8R6OWolOfRETrEg", "Argon2 сложный"),
    ("argon2", "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$+smq45/czydGj0lYNdZVXF++FOXJwrkXt6VUIcEauvo", "Argon2 очень сложный"),
]

def identify_algorithm(hash_str):
    hash_str = hash_str.strip()
    if hash_str.startswith(('$2a$', '$2b$', '$2y$')):
        return 'bcrypt'
    if hash_str.startswith('$argon2'):
        return 'argon2'
    if len(hash_str) == 32 and all(c in '0123456789abcdefABCDEF' for c in hash_str):
        return 'md5'
    if len(hash_str) == 40 and all(c in '0123456789abcdefABCDEF' for c in hash_str):
        return 'sha1'
    return None

def load_hashes_from_file(filename):
    hashes = []
    with open(filename, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            algo = identify_algorithm(line)
            if algo:
                hashes.append((algo, line, f"{algo}_{len(hashes)+1}"))
            else:
                print(f"Предупреждение: не удалось определить алгоритм для '{line}', пропускаем.")
    return hashes

def estimate_time(total_combinations, speed):
    if speed == 0:
        return float('inf')
    return total_combinations / speed

def format_time(seconds):
    if seconds == float('inf'):
        return "бесконечно"
    if seconds < 60:
        return f"{seconds:.1f} с"
    elif seconds < 3600:
        return f"{seconds/60:.1f} мин"
    elif seconds < 86400:
        return f"{seconds/3600:.1f} ч"
    else:
        return f"{seconds/86400:.1f} дн"

def check_password(password, targets):
    found = []
    pwd_bytes = password.encode('utf-8')
    
    md5_hash = hashlib.md5(pwd_bytes).hexdigest()
    if md5_hash in targets['md5']:
        found.append(targets['md5'][md5_hash])
        del targets['md5'][md5_hash]
    
    sha1_hash = hashlib.sha1(pwd_bytes).hexdigest()
    if sha1_hash in targets['sha1']:
        found.append(targets['sha1'][sha1_hash])
        del targets['sha1'][sha1_hash]
    
    for bcrypt_hash, name in list(targets['bcrypt'].items()):
        try:
            if bcrypt.checkpw(pwd_bytes, bcrypt_hash.encode('utf-8')):
                found.append(name)
                del targets['bcrypt'][bcrypt_hash]
        except:
            pass
    
    for argon2_hash, name in list(targets['argon2'].items()):
        try:
            ph.verify(argon2_hash, password)
            found.append(name)
            del targets['argon2'][argon2_hash]
        except:
            pass
    
    return found

def worker(start_chars, alphabet, pwd_length, targets, found_dict, stop_flag, lock, progress_counter, total_combinations):
    local_targets = {
        'md5': targets['md5'].copy(),
        'sha1': targets['sha1'].copy(),
        'bcrypt': targets['bcrypt'].copy(),
        'argon2': targets['argon2'].copy()
    }
    local_found = {}
    local_counter = 0
    
    for first in start_chars:
        if stop_flag.value:
            return
        for rest in itertools.product(alphabet, repeat=pwd_length-1):
            if stop_flag.value:
                return
            password = first + ''.join(rest)
            found_names = check_password(password, local_targets)
            local_counter += 1
            
            if local_counter % 1000 == 0:
                with lock:
                    progress_counter.value += 1000
            
            for name in found_names:
                local_found[name] = password
                with lock:
                    print(f"\n[НАЙДЕНО] {name}: {password}")
                if len(local_found) == (len(targets['md5']) + len(targets['sha1']) +
                                        len(targets['bcrypt']) + len(targets['argon2'])):
                    stop_flag.value = 1
                    break
    
    with lock:
        progress_counter.value += local_counter % 1000
    
    with lock:
        for name, pwd in local_found.items():
            found_dict[name] = pwd

def main():
    parser = argparse.ArgumentParser(description='Брутфорсер хэшей паролей с автоопределением алгоритмов')
    parser.add_argument('--hashes', nargs='+', help='Список хэшей в формате алгоритм:хэш:метка')
    parser.add_argument('--file', '-f', help='Файл с хэшами (по одному на строку)')
    parser.add_argument('--alphabet', default='abcdefghijklmnopqrstuvwxyz0123456789',
                        help='Алфавит для перебора')
    parser.add_argument('--min-len', type=int, default=1, help='Минимальная длина пароля')
    parser.add_argument('--max-len', type=int, default=6, help='Максимальная длина пароля')
    parser.add_argument('--processes', type=int, default=4, help='Количество процессов')
    parser.add_argument('--builtin', action='store_true', help='Используем встроенный список хэшей')
    parser.add_argument('--algo', nargs='+', choices=['md5', 'sha1', 'bcrypt', 'argon2'],
                        help='Фильтр по алгоритмам (перебирать только указанные)')
    parser.add_argument('--speed', type=float, default=1000000,
                        help='Оценочная скорость проверки (хэшей/сек) для расчёта времени')
    args = parser.parse_args()

    targets = {'md5': {}, 'sha1': {}, 'bcrypt': {}, 'argon2': {}}

    if args.builtin:
        print("Используем встроенный список хэшей")
        for algo, h, label in BUILTIN_HASHES:
            if args.algo and algo not in args.algo:
                continue
            targets[algo][h] = label
    elif args.file:
        hash_list = load_hashes_from_file(args.file)
        for algo, h, label in hash_list:
            if args.algo and algo not in args.algo:
                continue
            targets[algo][h] = label
    elif args.hashes:
        for item in args.hashes:
            try:
                algo, hash_val, label = item.split(':', 2)
            except ValueError:
                print(f'Ошибка формата: {item}. Должно быть алгоритм:хэш:метка')
                return
            if algo in targets:
                if args.algo and algo not in args.algo:
                    continue
                targets[algo][hash_val] = label
            else:
                print(f'Неизвестный алгоритм: {algo}')
                return
    else:
        print("Укажите --builtin, --file или --hashes")
        return

    total_targets = sum(len(t) for t in targets.values())
    if total_targets == 0:
        print('Нет целей для поиска (возможно, фильтр --algo исключил все)')
        return

    print(f'Целей: {total_targets}')
    print(f'Алфавит: {args.alphabet} (длина {len(args.alphabet)})')
    print(f'Диапазон длин: {args.min_len} - {args.max_len}')
    print(f'Процессов: {args.processes}')

    total_combs = 0
    alphabet_len = len(args.alphabet)
    for length in range(args.min_len, args.max_len + 1):
        total_combs += alphabet_len ** length
    print(f'Всего комбинаций: {total_combs:,}')
    
    est_seconds = estimate_time(total_combs, args.speed)
    print(f"Оценочное время при скорости {args.speed} хэш/сек: {format_time(est_seconds)}")
    if est_seconds > 3600 and args.speed < 1e7:
        print("Это может занять много времени. Рекомендуется уменьшить алфавит/длину или использовать --algo для фильтрации.")
    
    print("Начинаем перебор...")
    print("-" * 50)

    manager = Manager()
    found_dict = manager.dict()
    stop_flag = Value('i', 0)
    lock = manager.Lock()
    progress_counter = Value('i', 0)  

    start_time = time.time()
    last_report = time.time()

    for length in range(args.min_len, args.max_len + 1):
        if stop_flag.value:
            break
        print(f'\n--- Перебор длины {length} (всего {alphabet_len**length:,} комбинаций) ---')
        first_chars = list(args.alphabet)
        groups = [[] for _ in range(args.processes)]
        for i, ch in enumerate(first_chars):
            groups[i % args.processes].append(ch)

        processes = []
        for i in range(args.processes):
            p = Process(target=worker,
                        args=(groups[i], args.alphabet, length, targets, found_dict, stop_flag, lock,
                              progress_counter, total_combs))
            processes.append(p)
            p.start()

        
        while any(p.is_alive() for p in processes):
            time.sleep(2)
            now = time.time()
            if now - last_report >= 5:  
                with lock:
                    checked = progress_counter.value
                elapsed = now - start_time
                if checked > 0:
                    speed = checked / elapsed
                    remaining = total_combs - checked
                    eta = remaining / speed if speed > 0 else float('inf')
                    print(f"\rПрогресс: {checked}/{total_combs} ({checked/total_combs*100:.2f}%) | "
                          f"Скорость: {speed:.0f} хэш/с | ETA: {format_time(eta)}", end='', flush=True)
                last_report = now

        for p in processes:
            p.join()

    elapsed = time.time() - start_time
    print(f'\n\nВремя выполнения: {elapsed:.2f} с')
    print('Итоговые найденные пароли:')
    for name, pwd in found_dict.items():
        print(f'  {name}: {pwd}')

if __name__ == '__main__':
    main()

    #python bruteforcer.py --builtin --algo md5 sha1 --alphabet "0123456789" --min-len 6 --max-len 6
    #python bruteforcer.py --builtin --algo md5 sha1 --alphabet "abcdefghijklmnopqrstuvwxyz" --min-len 5 --max-len 5 --processes 4
# Protocols-practice-tracert
## Задача
Трассировка автономных систем. Пользователь вводит доменное имя
или IP адрес. Осуществляется трассировка до указанного узла (например, с использованием
tracert), т. е. мы узнаем IP адреса маршрутизаторов, через которые проходит пакет. Необходимо определить к какой автономной системе относится каждый из полученных IP адресов маршрутизаторов. Для определения номеров автономных систем обращаться к базам данных
региональных интернет регистраторов.
## Реализация
По заданному Ip или имени сайта программа выдает таблицу всех маршрутизаторов через которые осуществлялась трассировка.
Каждая запись содержит автономную систему к которой относится ip, а также страна и провайдер.
Этапы трассировки на которых результатом было **** игнорируются.

## Запуск
Для запуска требуются
* Python версии 3.10 и выше
* Установленные библиотеки из файла requirements.txt

Запуск происходит через терминал, в следующем формате `python tracer.py [ip/site name]`

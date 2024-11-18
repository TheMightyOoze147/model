% Путь к JAR-файлу JeroMQ
JARPATH = '/home/ubuntu/libs/jeromq-0.6.0/target/jeromq-0.6.0.jar';
javaclasspath(JARPATH)
import org.zeromq.*
% Инициализация контекста
context = ZContext();
% Создание сокетов для UE и ENB
ue_socket = context.createSocket(SocketType.REQ); % Используем REQ для запроса данных
ue_socket.connect('tcp://localhost:2000'); % Подключаемся к UE на порту 2000
enb_socket = context.createSocket(SocketType.REQ); % Используем REQ для запроса данных
enb_socket.connect('tcp://localhost:2001'); % Подключаемся к ENB на порту 2001
disp('Сокеты готовы. Ожидание данных...');
% Настройка графиков
figure;
hPlotUE = subplot(2, 1, 1); % Подграфик для UE
hPlotENB = subplot(2, 1, 2); % Подграфик для ENB
grid on;
xlabel(hPlotUE, 'Sample Index');
ylabel(hPlotUE, 'Amplitude');
title(hPlotUE, 'UE Samples');
xlabel(hPlotENB, 'Sample Index');
ylabel(hPlotENB, 'Amplitude');
title(hPlotENB, 'ENB Samples');
while true
 % Отправка запроса и получение данных от UE
 ue_socket.send('Request for samples from UE', 0);
 ue_reply = ue_socket.recv(0);

 if isempty(ue_reply)
 fprintf('No data received from UE.\n');
 ue_samples = [];
 else
 % Преобразование в массив uint32
 ue_samples_uint = typecast(ue_reply, 'uint32');

 % Преобразование uint32 данных в комплексные числа
 real_part_ue = bitshift(ue_samples_uint, -16); % Старшие 16 бит — реальная часть
 imag_part_ue = bitand(ue_samples_uint, uint32(65535)); % Младшие 16 бит — мнимая часть
 ue_samples = double(real_part_ue) + 1i * double(imag_part_ue);

 fprintf('Received %d complex samples from UE.\n', length(ue_samples));
 end

 % Обновление графика для UE, если есть данные
 if ~isempty(ue_samples)
 plot(hPlotUE, abs(ue_samples), 'b'); % Отображаем амплитуду
 xlim(hPlotUE, [0 length(ue_samples)]);
 drawnow;
 end

 % Отправка запроса и получение данных от ENB
 enb_socket.send('Request for samples from ENB', 0);
 enb_reply = enb_socket.recv(0);

 if isempty(enb_reply)
 fprintf('No data received from ENB.\n');
 enb_samples = [];
 else
 % Преобразование в массив uint32
 enb_samples_uint = typecast(enb_reply, 'uint32');

 % Преобразование uint32 данных в комплексные числа
 real_part_enb = bitshift(enb_samples_uint, -16); % Старшие 16 бит — реальная часть
 imag_part_enb = bitand(enb_samples_uint, uint32(65535)); % Младшие 16 бит — мнимая часть
 enb_samples = double(real_part_enb) + 1i * double(imag_part_enb);
 fprintf('Received %d complex samples from ENB.\n', length(enb_samples));
 end

 % Обновление графика для ENB, если есть данные
 if ~isempty(enb_samples)
 plot(hPlotENB, abs(enb_samples), 'r'); % Отображаем амплитуду
 xlim(hPlotENB, [0 length(enb_samples)]);
 drawnow;
 end

 pause(1);
end

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import socket
import time
import sys
import urllib.parse
import math

class UDPTesterGUI:
    def __init__(self, root):
        self.root = root
        self.root.title(" UDP GBPS ")
        self.root.geometry("1000x700")
        self.root.resizable(False, False)
        
        # Variables de control
        self.is_testing = False
        self.is_auto_mode = False
        self.test_thread = None
        self.auto_thread = None
        
        self.setup_ui()
        
    def setup_ui(self):
        # Frame principal
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Título
        title_label = ttk.Label(main_frame, 
                               text="UDP GBPS ", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Advertencia
        warning_label = ttk.Label(main_frame, 
                                 text=" ASTRA UDP ", 
                                 foreground="red",
                                 font=("Arial", 10, "bold"))
        warning_label.grid(row=1, column=0, columnspan=2, pady=(0, 10))
        
        # Configuración de destino
        config_frame = ttk.LabelFrame(main_frame, text="Configuración de Destino", padding="10")
        config_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Tipo de destino
        ttk.Label(config_frame, text="Tipo de Destino:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.dest_type = tk.StringVar(value="ip")
        ip_radio = ttk.Radiobutton(config_frame, text="IP", variable=self.dest_type, value="ip", command=self.toggle_dest_type)
        ip_radio.grid(row=0, column=1, sticky=tk.W, pady=5, padx=(10, 20))
        url_radio = ttk.Radiobutton(config_frame, text="URL", variable=self.dest_type, value="url", command=self.toggle_dest_type)
        url_radio.grid(row=0, column=2, sticky=tk.W, pady=5)
        
        # IP/URL de destino
        ttk.Label(config_frame, text="IP Destino:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.ip_entry = ttk.Entry(config_frame, width=20)
        self.ip_entry.grid(row=1, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=5, padx=(10, 0))
        self.ip_entry.insert(0, "127.0.0.1")  # Localhost por defecto
        
        # Puerto de destino
        ttk.Label(config_frame, text="Puerto Destino:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.port_entry = ttk.Entry(config_frame, width=20)
        self.port_entry.grid(row=2, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=5, padx=(10, 0))
        self.port_entry.insert(0, "8080")
        
        # Configuración de prueba
        test_frame = ttk.LabelFrame(main_frame, text="Configuración de Prueba", padding="10")
        test_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Modo de prueba
        ttk.Label(test_frame, text="Modo de Prueba:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.test_mode = tk.StringVar(value="packet_count")
        packet_radio = ttk.Radiobutton(test_frame, text="Por Paquetes", variable=self.test_mode, value="packet_count", command=self.toggle_test_mode)
        packet_radio.grid(row=0, column=1, sticky=tk.W, pady=5, padx=(10, 10))
        bandwidth_radio = ttk.Radiobutton(test_frame, text="Por Ancho de Banda", variable=self.test_mode, value="bandwidth", command=self.toggle_test_mode)
        bandwidth_radio.grid(row=0, column=2, sticky=tk.W, pady=5)
        
        # Número de paquetes (modo por paquetes)
        ttk.Label(test_frame, text="Número de Paquetes:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.packets_entry = ttk.Entry(test_frame, width=20)
        self.packets_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=(10, 0))
        self.packets_entry.insert(0, "100")
        
        # Duración (modo por ancho de banda)
        ttk.Label(test_frame, text="Duración (segundos):").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.duration_entry = ttk.Entry(test_frame, width=20)
        self.duration_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5, padx=(10, 0))
        self.duration_entry.insert(0, "10")
        
        # Ancho de banda objetivo
        ttk.Label(test_frame, text="Ancho de Banda (Mbps):").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.bandwidth_entry = ttk.Entry(test_frame, width=20)
        self.bandwidth_entry.grid(row=3, column=1, sticky=(tk.W, tk.E), pady=5, padx=(10, 0))
        self.bandwidth_entry.insert(0, "100")
        
        # Tamaño de paquete
        ttk.Label(test_frame, text="Tamaño (bytes):").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.size_entry = ttk.Entry(test_frame, width=20)
        self.size_entry.grid(row=4, column=1, sticky=(tk.W, tk.E), pady=5, padx=(10, 0))
        self.size_entry.insert(0, "1472")  # Tamaño óptimo para evitar fragmentación
        
        # Configuración de modo automático
        auto_frame = ttk.LabelFrame(main_frame, text="Modo Automático", padding="10")
        auto_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(auto_frame, text="Intervalo (segundos):").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.interval_entry = ttk.Entry(auto_frame, width=15)
        self.interval_entry.grid(row=0, column=1, sticky=tk.W, pady=5, padx=(10, 0))
        self.interval_entry.insert(0, "15")
        
        ttk.Label(auto_frame, text="Repeticiones:").grid(row=0, column=2, sticky=tk.W, pady=5, padx=(20, 0))
        self.repetitions_entry = ttk.Entry(auto_frame, width=15)
        self.repetitions_entry.grid(row=0, column=3, sticky=tk.W, pady=5, padx=(10, 0))
        self.repetitions_entry.insert(0, "0")  # 0 = infinito
        
        # Botones de control
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=5, column=0, columnspan=2, pady=20)
        
        self.start_button = ttk.Button(button_frame, text="Iniciar Prueba Única", command=self.start_single_test)
        self.start_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.auto_start_button = ttk.Button(button_frame, text="Iniciar Modo Automático", 
                                           command=self.start_auto_mode)
        self.auto_start_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_button = ttk.Button(button_frame, text="Detener Todo", 
                                     command=self.stop_all, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT)
        
        # Área de log
        log_frame = ttk.LabelFrame(main_frame, text="Log de Actividad", padding="10")
        log_frame.grid(row=6, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        self.log_text = tk.Text(log_frame, height=8, width=50, state=tk.DISABLED)
        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='determinate')
        self.progress.grid(row=7, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))
        
        # Estadísticas
        self.stats_label = ttk.Label(main_frame, text="Listo para comenzar")
        self.stats_label.grid(row=8, column=0, columnspan=2, pady=(10, 0))
        
        # Contador de ciclo automático
        self.cycle_label = ttk.Label(main_frame, text="", foreground="blue")
        self.cycle_label.grid(row=9, column=0, columnspan=2, pady=(5, 0))
        
        # Configurar pesos para responsive
        for i in range(10):
            main_frame.rowconfigure(i, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        config_frame.columnconfigure(1, weight=1)
        test_frame.columnconfigure(1, weight=1)
        auto_frame.columnconfigure(1, weight=1)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        # Inicializar la interfaz
        self.toggle_dest_type()
        self.toggle_test_mode()
        
    def toggle_dest_type(self):
        """Cambia la etiqueta según el tipo de destino seleccionado"""
        if self.dest_type.get() == "ip":
            config_frame = self.ip_entry.master
            for widget in config_frame.grid_slaves():
                if int(widget.grid_info()["row"]) == 1 and int(widget.grid_info()["column"]) == 0:
                    widget.config(text="IP Destino:")
                    break
        else:
            config_frame = self.ip_entry.master
            for widget in config_frame.grid_slaves():
                if int(widget.grid_info()["row"]) == 1 and int(widget.grid_info()["column"]) == 0:
                    widget.config(text="URL Destino:")
                    break
    
    def toggle_test_mode(self):
        """Cambia la interfaz según el modo de prueba seleccionado"""
        if self.test_mode.get() == "packet_count":
            self.packets_entry.config(state=tk.NORMAL)
            self.duration_entry.config(state=tk.DISABLED)
            self.bandwidth_entry.config(state=tk.DISABLED)
        else:
            self.packets_entry.config(state=tk.DISABLED)
            self.duration_entry.config(state=tk.NORMAL)
            self.bandwidth_entry.config(state=tk.NORMAL)
        
    def log_message(self, message):
        """Añade mensaje al log"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"{time.strftime('%H:%M:%S')} - {message}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
        
    def resolve_hostname(self, hostname):
        """Resuelve un nombre de host a una dirección IP"""
        try:
            self.log_message(f"Resolviendo {hostname}...")
            ip_address = socket.gethostbyname(hostname)
            self.log_message(f"Resuelto: {hostname} -> {ip_address}")
            return ip_address
        except socket.gaierror as e:
            raise Exception(f"No se pudo resolver el hostname: {hostname} - Error: {e}")
    
    def extract_hostname_from_url(self, url):
        """Extrae el hostname de una URL"""
        try:
            # Si la URL no tiene esquema, agregar uno para el parsing
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.hostname
            
            if not hostname:
                raise ValueError("URL no válida")
                
            return hostname
        except Exception as e:
            raise Exception(f"Error al parsear la URL: {e}")
    
    def validate_inputs(self):
        """Valida los datos de entrada"""
        try:
            dest = self.ip_entry.get().strip()
            port = int(self.port_entry.get())
            packet_size = int(self.size_entry.get())
            
            if not dest:
                messagebox.showerror("Error", "Debe ingresar una IP o URL destino")
                return False
                
            if self.test_mode.get() == "packet_count":
                packets = int(self.packets_entry.get())
                if packets <= 0 or packets > 1000000:
                    messagebox.showerror("Error", "Número de paquetes debe estar entre 1 y 1,000,000")
                    return False
            else:
                duration = int(self.duration_entry.get())
                bandwidth = float(self.bandwidth_entry.get())
                if duration <= 0 or duration > 3600:
                    messagebox.showerror("Error", "Duración debe estar entre 1 y 3600 segundos")
                    return False
                if bandwidth <= 0 or bandwidth > 1000:
                    messagebox.showerror("Error", "Ancho de banda debe estar entre 0.1 y 1000 Mbps")
                    return False
                
            if packet_size <= 0 or packet_size > 65507:  # Máximo tamaño UDP
                messagebox.showerror("Error", "Tamaño debe estar entre 1 y 65507 bytes")
                return False
                
            if port <= 0 or port > 65535:
                messagebox.showerror("Error", "Puerto debe estar entre 1 y 65535")
                return False
                
            return True
            
        except ValueError as e:
            messagebox.showerror("Error", "Por favor ingresa valores válidos")
            return False
    
    def get_resolved_ip(self):
        """Obtiene la IP resuelta según el tipo de destino"""
        dest = self.ip_entry.get().strip()
        
        if self.dest_type.get() == "ip":
            # Validar formato de IP
            try:
                socket.inet_aton(dest)
                return dest
            except socket.error:
                raise Exception(f"Formato de IP inválido: {dest}")
        else:
            # Es una URL, extraer hostname y resolver
            hostname = self.extract_hostname_from_url(dest)
            return self.resolve_hostname(hostname)
    
    def calculate_packet_rate(self, bandwidth_mbps, packet_size_bytes):
        """Calcula la tasa de paquetes por segundo para alcanzar el ancho de banda deseado"""
        # Convertir Mbps a bytes por segundo
        bandwidth_bytes_per_sec = (bandwidth_mbps * 1000000) / 8
        # Calcular paquetes por segundo
        packets_per_sec = bandwidth_bytes_per_sec / packet_size_bytes
        return packets_per_sec
    
    def start_single_test(self):
        """Inicia una prueba única"""
        if not self.validate_inputs():
            return
            
        if self.is_testing or self.is_auto_mode:
            messagebox.showwarning("Advertencia", "Ya hay una prueba en curso")
            return
            
        self.is_testing = True
        self.update_ui_state()
        
        try:
            # Obtener IP resuelta
            resolved_ip = self.get_resolved_ip()
            
            # Obtener parámetros
            port = int(self.port_entry.get())
            packet_size = int(self.size_entry.get())
            
            # Configurar según el modo de prueba
            if self.test_mode.get() == "packet_count":
                total_packets = int(self.packets_entry.get())
                duration = None
                target_bandwidth = None
                self.progress['maximum'] = total_packets
            else:
                duration = int(self.duration_entry.get())
                target_bandwidth = float(self.bandwidth_entry.get())
                total_packets = 0  # Ilimitado hasta que se alcance la duración
                self.progress['maximum'] = duration
                self.progress['value'] = 0
            
            dest_display = self.ip_entry.get()
            self.log_message(f"[PRUEBA ÚNICA] Iniciando prueba UDP a {dest_display} ({resolved_ip}:{port})")
            
            if self.test_mode.get() == "packet_count":
                self.log_message(f"Paquetes: {total_packets}, Tamaño: {packet_size} bytes")
            else:
                self.log_message(f"Duración: {duration}s, Ancho de banda: {target_bandwidth} Mbps")
            
            # Iniciar prueba en hilo separado
            self.test_thread = threading.Thread(
                target=self.run_udp_test,
                args=(resolved_ip, port, total_packets, packet_size, duration, target_bandwidth, dest_display, False),
                daemon=True
            )
            self.test_thread.start()
            
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.is_testing = False
            self.update_ui_state()
    
    def start_auto_mode(self):
        """Inicia el modo automático"""
        if not self.validate_inputs():
            return
            
        if self.is_testing or self.is_auto_mode:
            messagebox.showwarning("Advertencia", "Ya hay una prueba en curso")
            return
            
        try:
            interval = int(self.interval_entry.get())
            repetitions = int(self.repetitions_entry.get())
            
            if interval < 5:
                messagebox.showerror("Error", "El intervalo mínimo es 5 segundos")
                return
                
            if repetitions < 0:
                messagebox.showerror("Error", "Las repeticiones no pueden ser negativas")
                return
                
        except ValueError:
            messagebox.showerror("Error", "Por favor ingresa valores válidos para intervalo y repeticiones")
            return
            
        self.is_auto_mode = True
        self.update_ui_state()
        
        # Obtener IP resuelta al inicio
        try:
            resolved_ip = self.get_resolved_ip()
            dest_display = self.ip_entry.get()
            self.log_message(f"[MODO AUTOMÁTICO] Iniciando pruebas automáticas cada {interval} segundos")
            if repetitions > 0:
                self.log_message(f"Total de ciclos programados: {repetitions}")
            else:
                self.log_message(f"Ciclos infinitos - Use 'Detener Todo' para finalizar")
            
            # Iniciar modo automático en hilo separado
            self.auto_thread = threading.Thread(
                target=self.run_auto_mode,
                args=(resolved_ip, interval, repetitions, dest_display),
                daemon=True
            )
            self.auto_thread.start()
            
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.is_auto_mode = False
            self.update_ui_state()
    
    def run_auto_mode(self, ip, interval, repetitions, dest_display):
        """Ejecuta el modo automático con intervalos"""
        cycle_count = 0
        
        while self.is_auto_mode and (repetitions == 0 or cycle_count < repetitions):
            cycle_count += 1
            port = int(self.port_entry.get())
            packet_size = int(self.size_entry.get())
            
            # Configurar según el modo de prueba
            if self.test_mode.get() == "packet_count":
                total_packets = int(self.packets_entry.get())
                duration = None
                target_bandwidth = None
            else:
                duration = int(self.duration_entry.get())
                target_bandwidth = float(self.bandwidth_entry.get())
                total_packets = 0
            
            # Actualizar contador de ciclo
            self.root.after(0, self.update_cycle_counter, cycle_count, repetitions)
            
            self.root.after(0, self.log_message, f"[Ciclo {cycle_count}] Iniciando prueba...")
            
            # Ejecutar prueba única
            test_thread = threading.Thread(
                target=self.run_udp_test,
                args=(ip, port, total_packets, packet_size, duration, target_bandwidth, dest_display, True),
                daemon=True
            )
            test_thread.start()
            
            # Esperar a que termine la prueba actual
            test_thread.join(timeout=duration + 10 if duration else total_packets * 0.1 + 10)
            
            # Verificar si debemos continuar
            if not self.is_auto_mode:
                break
                
            # Esperar el intervalo antes del próximo ciclo (excepto después del último)
            if repetitions == 0 or cycle_count < repetitions:
                self.root.after(0, self.log_message, f"[Ciclo {cycle_count}] Esperando {interval} segundos...")
                
                # Espera con verificación periódica para poder detener
                for i in range(interval):
                    if not self.is_auto_mode:
                        break
                    time.sleep(1)
                    # Actualizar contador de espera
                    remaining = interval - i - 1
                    self.root.after(0, self.update_wait_counter, remaining)
        
        self.root.after(0, self.auto_mode_completed)
    
    def run_udp_test(self, ip, port, total_packets, packet_size, duration, target_bandwidth, dest_display, is_auto_mode):
        """Ejecuta la prueba UDP en un hilo separado"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.1)  # Timeout corto para no bloquear la salida
            
            # Configurar buffer de envío más grande para mejor rendimiento
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
            
            test_data = b"X" * packet_size
            packets_sent = 0
            start_time = time.time()
            last_update_time = start_time
            
            # Calcular intervalo entre paquetes si se usa modo de ancho de banda
            if target_bandwidth is not None:
                packets_per_second = self.calculate_packet_rate(target_bandwidth, packet_size)
                packet_interval = 1.0 / packets_per_second
                if not is_auto_mode:
                    self.root.after(0, self.log_message, f"Objetivo: {packets_per_second:.2f} paquetes/segundo")
            else:
                packet_interval = 0
            
            # Bucle principal de envío
            while (self.is_testing or self.is_auto_mode) and not (is_auto_mode and not self.is_auto_mode):
                current_time = time.time()
                elapsed_time = current_time - start_time
                
                # Verificar si hemos alcanzado el límite de tiempo
                if duration is not None and elapsed_time >= duration:
                    break
                
                # Verificar si hemos alcanzado el límite de paquetes
                if total_packets > 0 and packets_sent >= total_packets:
                    break
                
                try:
                    # Enviar paquete
                    sock.sendto(test_data, (ip, port))
                    packets_sent += 1
                    
                    # Actualizar estadísticas periódicamente
                    if current_time - last_update_time >= 0.5:  # Actualizar cada 500ms
                        self.root.after(0, self.update_progress, packets_sent, elapsed_time, 
                                      total_packets, duration, start_time)
                        last_update_time = current_time
                    
                    # Controlar tasa de envío para alcanzar el ancho de banda deseado
                    if packet_interval > 0:
                        next_packet_time = start_time + (packets_sent * packet_interval)
                        sleep_time = next_packet_time - time.time()
                        if sleep_time > 0:
                            time.sleep(sleep_time)
                    
                except socket.error as e:
                    if not is_auto_mode:
                        self.root.after(0, self.log_message, f"Error de socket: {e}")
                    break
                except Exception as e:
                    if not is_auto_mode:
                        self.root.after(0, self.log_message, f"Error enviando paquete: {e}")
                    break
            
            end_time = time.time()
            total_time = end_time - start_time
            
            # Resultados finales
            if not is_auto_mode:
                self.root.after(0, self.test_completed, packets_sent, total_time, dest_display, packet_size)
            else:
                self.root.after(0, self.auto_test_completed, packets_sent, total_time, packet_size)
            
        except Exception as e:
            if not is_auto_mode:
                self.root.after(0, self.log_message, f"Error en la prueba: {e}")
        finally:
            try:
                sock.close()
            except:
                pass
            
    def update_progress(self, packets_sent, elapsed_time, total_packets, duration, start_time):
        """Actualiza la barra de progreso y estadísticas"""
        if self.test_mode.get() == "packet_count":
            self.progress['value'] = packets_sent
            if total_packets > 0:
                percentage = (packets_sent / total_packets) * 100
        else:
            self.progress['value'] = elapsed_time
            if duration > 0:
                percentage = (elapsed_time / duration) * 100
        
        if elapsed_time > 0:
            rate = packets_sent / elapsed_time
            bandwidth = (packets_sent * int(self.size_entry.get()) * 8) / elapsed_time / 1000000  # Mbps
            stats_text = f"Paquetes: {packets_sent} | Rate: {rate:.1f} pkt/s | BW: {bandwidth:.2f} Mbps"
            self.stats_label.config(text=stats_text)
    
    def update_cycle_counter(self, current_cycle, total_cycles):
        """Actualiza el contador de ciclos"""
        if total_cycles > 0:
            self.cycle_label.config(text=f"Ciclo: {current_cycle}/{total_cycles}")
        else:
            self.cycle_label.config(text=f"Ciclo: {current_cycle} (∞)")
    
    def update_wait_counter(self, seconds_remaining):
        """Actualiza el contador de espera"""
        self.cycle_label.config(text=f"Próximo ciclo en: {seconds_remaining}s")
    
    def test_completed(self, packets_sent, total_time, dest_display, packet_size):
        """Maneja la finalización de una prueba única"""
        self.is_testing = False
        self.log_message(f"[PRUEBA ÚNICA] Completada a {dest_display}")
        self.log_message(f"Paquetes enviados: {packets_sent} en {total_time:.2f} segundos")
        
        if total_time > 0:
            rate = packets_sent / total_time
            bandwidth = (packets_sent * packet_size * 8) / total_time / 1000000  # Mbps
            self.log_message(f"Tasa promedio: {rate:.2f} paquetes/segundo")
            self.log_message(f"Ancho de banda promedio: {bandwidth:.2f} Mbps")
        
        self.update_ui_after_test()
    
    def auto_test_completed(self, packets_sent, total_time, packet_size):
        """Maneja la finalización de una prueba en modo automático"""
        if total_time > 0:
            rate = packets_sent / total_time
            bandwidth = (packets_sent * packet_size * 8) / total_time / 1000000  # Mbps
            self.log_message(f"[AUTO] Enviados {packets_sent} paquetes en {total_time:.2f}s ({rate:.1f} pkt/s, {bandwidth:.2f} Mbps)")
    
    def auto_mode_completed(self):
        """Maneja la finalización del modo automático"""
        self.is_auto_mode = False
        self.log_message("[MODO AUTOMÁTICO] Finalizado")
        self.update_ui_after_test()
    
    def stop_all(self):
        """Detiene todas las pruebas en curso"""
        self.is_testing = False
        self.is_auto_mode = False
        self.log_message("Deteniendo todas las pruebas...")
        self.update_ui_after_test()
    
    def update_ui_state(self):
        """Actualiza el estado de los botones"""
        if self.is_testing or self.is_auto_mode:
            self.start_button.config(state=tk.DISABLED)
            self.auto_start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
        else:
            self.start_button.config(state=tk.NORMAL)
            self.auto_start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
    
    def update_ui_after_test(self):
        """Restaura la UI después de la prueba"""
        self.is_testing = False
        self.update_ui_state()
        self.progress['value'] = 0
        self.cycle_label.config(text="")
        if not self.is_auto_mode:
            self.stats_label.config(text="Prueba finalizada")

def main():
    root = tk.Tk()
    app = UDPTesterGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
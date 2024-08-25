import pandas as pd
import matplotlib.pyplot as plt

# Cargar el archivo CSV
file_path = './data/all_logs.csv'
logs_df = pd.read_csv(file_path)

# Filtrar los logs para obtener solo los relacionados con END_REGISTRATION
end_registration_logs = logs_df[logs_df['log_type'] == 'END_PREREGISTRATION']

# Agrupar por agente y calcular el tiempo promedio de preregistro
average_preregistration_time = end_registration_logs.groupby('agent_name')['time'].mean().sort_values(ascending=False).head(10)
# Crear la gráfica nuevamente con el tiempo mostrado encima de cada barra

plt.figure(figsize=(12, 6))
bars = average_preregistration_time.plot(kind='bar', color='skyblue')
plt.title('Tiempo Promedio de Preregistro de los 10 Agentes Principales')
plt.xlabel('Nombre del Agente')
plt.ylabel('Tiempo de Preregistro (s)')
plt.xticks(rotation=45)
plt.ylim(0, 2)  # Ajustar el rango del eje y para que llegue hasta 2 segundos
plt.tight_layout()

# Añadir etiquetas encima de cada barra
for bar in bars.patches:
    plt.text(bar.get_x() + bar.get_width() / 2, 
             bar.get_height(), 
             f'{bar.get_height():.2f}', 
             ha='center', 
             va='bottom')

# Guardar la gráfica en un archivo local
output_path = './data/all-logs-preregistration-time.png'
plt.savefig(output_path)
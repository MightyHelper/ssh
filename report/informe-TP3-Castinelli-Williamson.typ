#set document(
  author: "Federico Williamson, Leonel Castinelli",
  title: "SSH Handshake",
  date: datetime.today(),
  keywords: ("SSH", "Handshake", "SSH Handshake"),
)
#set text(lang: "es", font: "New Computer Modern")
#set par(justify: true)
#show regex("RFC(\d{4})(-([0-9.]+))?"): x=>text(fill:blue, link("https://www.ietf.org/rfc/rfc"+x.text.slice(3, 7)+".txt", x))
#set heading(numbering: "I.")
#show heading.where(level: 1): x => [
  #text(font: "PT Serif", x)
]
#show heading.where(level: 1): x => text(size: 1.5em, x)
#let important = x => block(fill: green.transparentize(50%), stroke: green.darken(50%) + 2pt, radius: 1em, inset: 1em, x)
#let handinTitle(name, date, title, subject) = {[
  #set document(author: name, date: date, title: [#subject - #name])
#align(top)[
  #text(size: 1.5em)[#name#h(1fr)#date.display("[year]/[month]/[day]")]
]
#align(center)[
  #text(size: 3em, [#heading(numbering: none, level: 1, [#title])])#linebreak()
  #text(size: 2em, [#subject])
]
]}
#page[
  #place(
    center+horizon,
    box(width: 75%, clip: true, radius: 50%, image("images/robot_handshake.png"))
  )
  #place(
    center+horizon,
    dy: -35%,
    text(size: 5em,[SSH Handshake])
  )
  
  #place(
    center+horizon,
    dy: 35%,
    [
      #text(size: 3em,[
        - Federico Williamson
        - Leonel Castinelli
      ])
      
      #text(size: 2em,[Seguridad Informática 2024])
    ]
  )
]

#outline(depth: 2)
#set page(numbering: "1 de 1")

= Introducción

== ¿Qué es SSH?

#strong[SSH] (o #strong[Secure SHell]) es el nombre un protocolo y del programa que lo implementa 
cuya principal función es el #strong[acceso remoto] a un servidor por medio de un 
#strong[canal seguro] en el que toda la información está cifrada. El puerto 
TCP asignado de forma predeterminada es el puerto #strong[22], asignado por la IANA @sshStoryPort.

== Descripción técnica del problema que soluciona.

Ante la comunicación entre dos equipos informáticos, existe la posible amenaza de que un equipo malicioso esté escuchando la comunicación legítima y busque
robar información que se esté transmitiendo o incluso intente robar la identidad de uno de los actores en la comunicación para inducir mensajes maliciosos en la misma.

== Principales aplicaciones.

Ya que este protocolo prueba ser de extrema utilidad, se aplica en las siguientes ocasiones:

- Acceso Remoto Seguro: Permite controlar equipos informáticos de forma segura a través de internet.
- Túneles SSH: Redirección de tráfico en la red a través de un canal seguro, útil para evitar restricciones de red y proteger datos sensibles.
- Transferencia segura de archivos: Los protocolos SCP y SFTP utilizan el protocolo SSH para la transferencia de archivos de forma s 

== ¿Qué es SSH Handshake?

Es un proceso por el cual se establece una conexión segura entre un cliente y un servidor. Se produce tras la primera comunicación con el servidor. Consta de #strong[5 pasos]:

- #strong[Paso 1:] Intercambio de Versiones.
- #strong[Paso 2:] Intercambio de Claves (KEX).
- #strong[Paso 3:] Inicialización de Elliptic Curve Diffie-Hellman (ECDH).
- #strong[Paso 4:] Respuesta de ECDH.
- #strong[Paso 5:] Nuevas Claves (NewKeys).

#pagebreak()
= Intercambio de Versiones.

== Cadena de Version#footnote[RFC4253-4.2]
La cadena de versión de un participante en la comunicación se encuentra en el siguiente formato:

```python
<SSH-protocolversion>-<softwareversion> <comments>CRLF
```

Con esta cadena en este formato ambos participantes podrán intercambiar la versión del protocol que están utilizando y la versión de software que están utilizando.
Y siempre deben terminar con CRLF#footnote[CRLF es un `\r` seguido de `\n`].@ietfRFC4253

Ambas partes, #strong[cliente] y #strong[servidor] deben enviar sus cadenas de versión. Las cuales llamaremos $V_C$ a la cadena de version del #strong[cliente] y $V_S$
a la del #strong[servidor].

#image("images/exec-1.png")

Acá podemos observar como enviamos nuestra versión y recibimos la versión del servidor.

== Protocolo binario de paquetes

Cada paquete se encuentra en el siguient

```awk
uint32    packet_length
byte      padding_length
byte[n1]  payload; n1 = packet_length - padding_length - 1
byte[n2]  random padding; n2 = padding_length
byte[m]   mac (Message Authentication Code - MAC); m = mac_length
```
Donde cada parte representa:
- *packet_length*: Es la longitud del paquete en bytes, sin contar 'mac' o el mismo campo 'packet_length'
- *padding_length*: longitud del 'random padding' en bytes.
- *payload*: La parte útil del paquete.
- *random_padding*: padding de longitud arbitraria, para que la longitud total (packet_length + padding_length + payload + random_padding) sea un múltiplo de 8, el padding tiene que ser cómo mínimo de 4 y máximo de 255. Además sirve para introducr ruido al mensaje, confundiendo a receptores ilegítimos de la comunicación.
- *MAC*: Código de Autorización de Mensajes, si se negoció la autenticación de mensajes, este campo contiene los bytes de MAC. Inicialmente el algoritmo de MAC es `none`. 


=== MAC

Una funcionalidad de proteccion, de extrema utilidad en lo que concierne a la seguridad de la comunicación, que ofrece SSH en su modelo de paquetes es MAC: Message Authorization Code (Código de Autorizacón de Mensajes).

Este codigo es un algoritmo de hash del contenido del mensaje no encriptado, con un número de secuencia del paquete.

Esto es extremadamente util en evitar replay attacks.

= Intercambio de algoritmos (KEXInit)#footnote[RFC4253-7.1] <kex-init>

#image("images/exec-2.png")
Nosotros mandamos este paquete de tipo KEX init al servidor.

Aca manifestamos los algoritmos que soportamos para cada categoria, en orden descendente de preferencia. 
Para forzar el uso de ciertos algoritmos y simplificar la implementación, enviamos listas de un único elemento. 

#image("images/exec-3.png")


La respuesta del servidor, mostrando todos los algoritmos que soporta para cada categoria.

El protocolo SSH define que se usa el primero en comun, llendo en orden de izquierda a derecha.

Es posible que en cada direccion se usen algirtmos distintos

En este momentto, hambos cliente y servidor saben que algoritmo van a usar para cada caso (lo pueden inferir por separado)

A los *payload* de *cliente* y *servidor* los llamaremos $I_C$ y $I_S$ respectivamente

= Intercambio de claves Diffie Hellman#footnote[RFC4253-8]

Nosotros, elegimos usar el algoritmo de `diffie-hellman-group14-sha256` como algoritmo de intercambio.

Esto significa que:
- Vamos a hacer un intercambio de tipo DH. (que usará Curvas Elípticas Diffie-Hellman, ECDH)
- Vamos a usar primos del grupo 14.
- Vamos a usar sha256 como algoritmo de hash.

#important[
  El objetivo del KEX DH es que ambos participantes puedan mutuamente acordar en una clave igual, sin que esta sea derivable por un tercero que esta observando la comunicación.
]

Como funciona esto?

1. Se acuerdan $p$ y $g$. P es un primo publico muy grande, y $g$ su generador.

Como estamos usando group14, usamos el primos del grupo 14, que esta definido en RFC3526-3

C (cliente) genera un numero aleatorio $x$ entre $1$ y $q$#footnote[$q$ hace referencia al orden del subgrupo, que no se necesita clacular explicitamente, es aproximadamente $floor(p / 2)$] y computa el valor:
#figure($e = g^x mod p$)

El cual es conocido como *clave pública del cliente* y a $x$ lo llamaremos *clave privada del cliente*.

#image("images/exec-4.png")


S (servidor) genera su propio numero aleatorio $y$ entre $0$ y $q$ y computa:
#figure($f = g^y mod p$)

Acá se puede observar la *clave pública del servidor* $f$ y la *clave privada del servidor* $y$.

#image("images/exec-5.png")

S al recibir e, computa el *secreto compartido* $K$ de la siguiente forma:
#figure($ K = e^y mod p$)

Una vez que ves. recibe $x$ del C, ya esta listo y manda `SSH_NEW_KEYS`.
Cuando C recibe $f$ de S, puede emitir `SSH_NEW_KEYS`.

#image("images/exec-6.png")

#image("images/finally.jpg")

En este momento ambos tienen suficiente información para terminar de derivar la clave compartida $K$, pero únicamente $K$ es insuficiente para la comunicación

y tambien computa el hash $H$:
#figure($H = "hash"(V_C || V_S || I_C || I_S || K_S || e || f || K)$)
Donde:
- $"hash"$ es sha256, por el algoritmo de intercambio que elegimos,
- $V_C$ Es la version de ssh cliente (sin CRLF)
- $V_S$ Version de ssh del seervidor (sin CRLF)
- $I_C$ El Payload del `KEX_INIT` enviado por el cliente
- $I_S$ El Payload del `KEX_INIT` enviado por el servidor
- $K_S$ La Host-Key del servidor#footnote[Este es un valor adicional que envia el servidor cuando envia $f$, con el proposito de autenticarse.]
- $e$ La clave publica del cliente
- $f$ La clave privada del servidor
- $K$ el secreto compartido entre las partes.

Un dato interesante de esto, es que al incluir el payload de $I_C$ e $I_S$, que como anteriormente cubrimos en @kex-init, contienen un cookie que contiene un valor random. Esto hace que sea completamente imposible para un atacante determinar $H$ en sesiones repetidas.


En base a H, K y la session id#footnote[La session id es el primer H que se acuerda entre C y S, y no cambia cuando hay un reset de keys.] se calculan los siguientes valores:
```
o  Initial IV client to server: HASH(K || H || "A" || session_id)
  (Here K is encoded as mpint and "A" as byte and session_id as raw
  data.  "A" means the single character A, ASCII 65).
o  Initial IV server to client: HASH(K || H || "B" || session_id)
o  Encryption key client to server: HASH(K || H || "C" || session_id)
o  Encryption key server to client: HASH(K || H || "D" || session_id)
o  Integrity key client to server: HASH(K || H || "E" || session_id)
o  Integrity key server to client: HASH(K || H || "F" || session_id)
```

== Markus

Para probar el cliente, con el servidor de openssh, es posible ejecutarlo en modo debug. Una de las funcionalidades del modo debug, es una vez que se inicia la comunicacion encriptada, se envia un paquete de tipo 02 (`SSH_IGNORE`) con texto: `markus`. Este mensaje conocido es extremadamente util para debuggear problemas.

`markus` en este caso hace referencia a Markus Friedl, un contribuidor original de SSH.

#image("images/exec-7.png")

Aca se puede observar como tambien enviamos un paquete ignorable con `markus` al servidor para verificar que no produce errores.

== Solicitud de servicio#footnote[RFC4252]

Antes de proceder, requerimos que el servidor nos permita autenticar usuarios.

#image("images/exec-8.png")

== Solicitud de Conexion#footnote[RFC4252]

Una vez que tenemos permisos para autenticar, podemos solicitar una conexion

#image("images/exec-9.png")

Una vez que realizamos esto, si es exitosa, recibimos varios mensajes del servidor:

+ HostKeys: Autenticacion del servidor
+ Confirmacion de la apertura del canal

#image("images/exec-10.png")

Y estamos en posicion de enviar un comando

== Ejecucion#footnote[RFC4254]

#image("images/exec-11.png")

Enviamos un comando de EXEC con payload `echo hi`

Y recibimos varios mensajes del servidor:
- `SSH2_MSG_CHANNEL_WINDOW_ADJUST`: Incrementando el tamaño maximo de un paquete.
- `SSH2_MSG_CHANNEL_EXTENDED_DATA`: Con informacion del path, y otras variables de entorno
- `SSH2_MSG_CHANNEL_REQUEST`: Pide abrir un canal de comunicacion hacia nosotros
- `SSH2_MSG_CHANNEL_DATA`: Optimisticamente envia la respuesta a nuestra peticion antes que aceptemos abrir el canal.



#image("images/exec-12.png")

= Apéndice I

#align(center)[
  #image("./images/ssh-steps.svg")
]


#pagebreak()
#bibliography("refs.bib")

Los RFC mencionados tienen links.

#set document(
  author: "Federico Williamson, Leonel Castinelli",
  title: "SSH Handshake",
  date: datetime.today(),
  keywords: ("SSH", "Handshake", "SSH Handshake"),
)
#set text(lang: "es", font: "New Computer Modern")
#set par(justify: true)
#show regex("RFC(\d{4})(-([0-9.]+))?"): x=>text(fill:blue, link("https://www.ietf.org/rfc/rfc"+x.text.slice(3, 7)+".txt", x))
#set heading(numbering: "I.1.")
#show heading.where(level: 1): x => [
  #text(font: "PT Serif", x)
]
#set math.equation(numbering: "(1)")
#let unb = x => block(breakable: false, x)
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
        Federico Williamson
        
        Leonel Castinelli
      ])
      
      #text(size: 2em,[Seguridad Informática 2024])
    ]
  )
]

#outline(depth: 2)
#set page(numbering: "1 de 1")
#columns(2)[


= Introducción

== ¿Qué es SSH?

*SSH* (o *Secure SHell*) es el nombre de un protocolo y del programa que lo implementa 
cuya principal función es el *acceso remoto* a un servidor por medio de un 
*canal seguro* en el que toda la información está cifrada. El puerto 
TCP asignado de forma predeterminada es el puerto *22*, asignado por la IANA @sshStoryPort.

== Problema que soluciona

Ante la comunicación entre dos equipos informáticos, existe la posible amenaza de que un equipo malicioso esté escuchando la comunicación legítima y busque
robar información que se esté transmitiendo o incluso intente robar la identidad de uno de los actores en la comunicación para inducir mensajes maliciosos en la misma.

== Principales aplicaciones

Ya que este protocolo prueba ser de extrema utilidad, se aplica en las siguientes ocasiones:

- *Acceso Remoto Seguro*: Permite controlar equipos informáticos de forma segura a través de internet.
- *Reenvío de puertos*: Permite el acceso a servicios restringidos en redes privadas por medio de reenvío de puertos.
- *Túneles SSH*: Redirección de tráfico en la red a través de un canal seguro, útil para evitar restricciones de red y proteger datos sensibles.
- *Transferencia segura de archivos*: Los protocolos SCP y SFTP utilizan el protocolo SSH para la transferencia de archivos de forma segura.

== ¿Qué es el Handshake SSH?

Es un proceso por el cual se establece una conexión segura entre un cliente y un servidor. Se produce tras la primera comunicación con el servidor. Consta de *5 pasos*:

+ Intercambio de Versiones.
+ Intercambio de Claves (KEX).
+ Inicialización de intercambio Diffie-Hellman (DH).
+ Respuesta de DH.
+ Nuevas Claves (NewKeys).
= El protocolo
== Intercambio de Versiones#footnote[RFC4253-4.2]

=== Cadena de Version#footnote[RFC4253-4.2]
La cadena de versión de un participante en la comunicación se encuentra en el siguiente formato:

```python
<SSH-protocolversion>-<softwareversion> <comments>CRLF
```

Con esta cadena en este formato ambos participantes podrán intercambiar la versión del protocolo y la versión de software que están utilizando.
Siempre deben terminar con CRLF#footnote[CRLF es un `\r` seguido de `\n`] @ietfRFC4253.

Ambas partes, *cliente* y *servidor* deben enviar sus cadenas de versión. Las cuales llamaremos $V_C$ a la cadena de version del *cliente* y $V_S$
a la del *servidor*.

#figure(
  image("images/exec-1.png"),
  caption: "Intercambio de versiones"
) <version-exchange>

En la @version-exchange podemos observar como enviamos nuestra versión y recibimos la versión del servidor.

=== Protocolo binario de paquetes

Cada paquete se encuentra en el siguiente formato:
#unb[
  ```awk
  uint32    packet_length
  byte      padding_length
  byte[n1]  payload; n1 = packet_length - padding_length - 1
  byte[n2]  random padding; n2 = padding_length
  byte[m]   mac (Message Authentication Code - MAC); m = mac_length
  ```
]
Donde cada parte representa:
- *packet_length*: Es la longitud del paquete en bytes, sin contar 'mac' o el mismo campo 'packet_length'.
- *padding_length*: longitud del 'random padding' en bytes.
- *payload*: La parte útil del paquete.
- *random_padding*: padding de longitud arbitraria, para que la longitud total (packet_length + padding_length + payload + random_padding) sea un múltiplo de 8#footnote[O multiplo del tamaño de bloque del algoritmo de cifrado si este esta en efecto], el padding tiene que ser como mínimo de 4 y máximo de 255. Además sirve para introducr ruido al mensaje, confundiendo a receptores ilegítimos de la comunicación.
- *MAC*: Código de Autorización de Mensajes, si se negoció la autenticación de mensajes, este campo contiene los bytes de MAC. Inicialmente el algoritmo de MAC es `none`. 


==== MAC

Una funcionalidad de protección, de extrema utilidad en lo que concierne a la seguridad de la comunicación, que ofrece SSH en su modelo de paquetes, es MAC: Message Authorization Code (Código de Autorización de Mensajes).

Este código es un algoritmo de hash del contenido del mensaje no encriptado, concatenado con el número de secuencia del paquete.

Esto es extremadamente útil en evitar replay attacks, entre otros.

== Intercambio de algoritmos (KEXInit)#footnote[RFC4253-7.1] <kex-init>

SSH es un protocolo muy versátil, permite utilizar múltiples algoritmos para cada parte de la comunicación.

A efectos de determinar el algoritmo que se va a utilizar para esta conexión, es necesario que el servidor y el cliente intercambien los algoritmos que soportan.

#figure(
  image("images/exec-2.png"),
  caption: [Kex Init del cliente enviado a remoto]
) <client-kex-init>
Nosotros mandamos el paquete de tipo KEX init mostrado en la @client-kex-init al servidor.

Aca manifestamos los algoritmos que soportamos para cada categoria, en orden descendente de preferencia.
Para forzar el uso de ciertos algoritmos y simplificar la implementación, enviamos listas de un único elemento. 

#figure(
  image("images/exec-3.png"),
  caption: [Kex Init recibido del servidor]
) <server-kex-init>


En la @server-kex-init se puede ver la respuesta del servidor, mostrando todos los algoritmos que soporta para cada categoria.

El protocolo SSH (RFC4253) define que se usa el primero en comun, llendo en orden de izquierda a derecha.

Es posible que en cada direccion de la comunicación #footnote[cliente a servidor, servidor a cliente] se usen algirtmos distintos.

En este momento, hambos cliente y servidor saben que algoritmo van a usar para cada caso (lo pueden inferir sin necesidad de transmitirlo).

A los *payload* de KEX Init que envian el *cliente* y el *servidor* seran utilizados luego y los llamaremos $I_C$ y $I_S$ respectivamente.

== Intercambio de claves Diffie Hellman#footnote[RFC4253-8]

Nosotros, elegimos usar el algoritmo de `diffie-hellman-group14-sha256` como algoritmo de intercambio.

Esto significa que:
- Vamos a hacer un intercambio de tipo DH.
- Vamos a usar primos del grupo 14.
- Vamos a usar sha256 como algoritmo de hash.

#important[
  El objetivo de KEX DH es que ambos participantes puedan mutuamente acordar en una clave, sin que esta sea derivable por un tercero que esta observando la comunicación.
]

Como funciona esto?

1. Se acuerdan $p$ y $g$. $p$ es un primo publico muy grande, y $g$ su generador.

Como estamos usando group14, usamos el primos del grupo 14, que esta definido en RFC3526-3.

C (cliente) genera un número aleatorio $x$ entre $1$ y $q$#footnote[$q$ hace referencia al orden del subgrupo, que en la práctica, no se necesita calcular explícitamente, es aproximadamente $floor(p / 2)$] y computa el valor:

$ e = g^x mod p $ <client-pk>

En la @client-pk, $e$ es la *clave pública del cliente* y a $x$ lo llamaremos *clave privada del cliente*.

#figure(
  image("images/exec-4.png"),
  caption: [Generacion de clave privada y clave publica por parte del cliente.]
) <client-dh-gen>


S (servidor) genera su propio numero aleatorio $y$ entre $0$ y $q$ y computa:

$ f = g^y mod p $ <server-pk>

En la @server-pk se puede observar la *clave pública del servidor* $f$ y la *clave privada del servidor* $y$.


#figure(
  image("images/exec-5.png"),
  caption: [Generacion de clave privada y clave publica por parte del servidor.]
) <server-dh-gen>


S al recibir e, computa el *secreto compartido* $K$ de la siguiente forma:

$ K = e^y mod p $ <shared-k>

Una vez que S recibe $x$ del C, tiene toda la informacion para derivar la clave y manda `SSH_NEW_KEYS`.
Cuando C recibe $f$ de S, puede calcular el secreto compartido y emitir `SSH_NEW_KEYS`.

#figure(
  image("images/exec-6.png"),
  caption: [El secreto compartido]
) <shared-k-value>

En este momento ambos tienen suficiente información para terminar de derivar la clave compartida $K$, pero con solo $K$, resulta insuficiente para la comunicación.

Es necesario seguir los siguientes pasos:
*Computar el hash $H$*:
#math.equation($ H = "hash"(V_C || V_S || I_C || I_S || K_S || e || f || K) $, numbering: none, block: true) <hash-h>
Donde:
- $"hash"$ es sha256, por el algoritmo de intercambio que elegimos
- $V_C$ Es la version de ssh cliente (sin CRLF)
- $V_S$ Version de ssh del seervidor (sin CRLF)
- $I_C$ El Payload del `KEX_INIT` enviado por el cliente
- $I_S$ El Payload del `KEX_INIT` enviado por el servidor
- $K_S$ La Host-Key del servidor#footnote[Este es un valor adicional que envia el servidor cuando envia $f$, con el proposito de autenticarse.]
- $e$ La clave publica del cliente
- $f$ La clave privada del servidor
- $K$ el secreto compartido entre las partes.

Un dato interesante de esto, es que al incluir el payload de $I_C$ e $I_S$, que como anteriormente cubrimos en @kex-init, contienen un cookie que contiene un valor random. Esto hace que sea completamente imposible para un atacante determinar $H$ en sesiones repetidas.

#important[
  En base a $H$, $K$ y la session id#footnote[La session id es el primer $H$ que se acuerda entre $C$, y $S$, y no cambia cuando hay un reset de keys.] se calculan los siguientes valores:
  - Primer IV C $arrow.r$ S: $"HASH"(K || H || 'A' || "session_id")$#footnote[$K$ esta encodeado como `mpint`, $A$ es el byte encodeado en ASCII y `session_id` no esta encodeado]
  - Primer IV C $arrow.l$ S: $"HASH"(K || H || 'B' || "session_id")$
  - Clave de Encriptación C $arrow.r$ S: $"HASH"(K || H || 'C' || "session_id")$
  - Clave de Encriptación C $arrow.l$ S: $"HASH"(K || H || 'D' || "session_id")$
  - Clave de MAC C $arrow.r$ S: $"HASH"(K || H || 'E' || "session_id")$
  - Clave de MAC C $arrow.l$ S: $"HASH"(K || H || 'F' || "session_id")$
]

#figure(
  image("images/finally.jpg"),
  caption: [Dícese que es una imagen del servidor o el cliente tomada inmediatamente después de derivar las claves para la comunicación.]
)


=== Markus

Para probar el cliente, con el servidor de OpenSSH, es posible ejecutarlo en modo debug. Una de las funcionalidades del modo debug, es una vez que se inicia la comunicación encriptada, se envía un paquete de tipo 02 (`SSH_IGNORE`) con texto: `markus`. Este mensaje conocido es extremadamente útil para debuggear problemas.

`markus` en este caso hace referencia a Markus Friedl, un contribuidor original de SSH.

#figure(
  image("images/exec-7.png"),
  caption: [Mensaje ignorable `Markus`]
) <markus-exchange>

En la @markus-exchange se puede observar como tambien enviamos un paquete ignorable con `markus` al servidor para verificar que no produce errores.

== Solicitud de servicio#footnote[RFC4252]

Antes de proceder, requerimos que el servidor nos permita autenticar usuarios.

#figure(
  image("images/exec-8.png"),
  caption: [Solicitud de servicio `ssh-authuser`]
)

== Solicitud de Conexion#footnote[RFC4252]

Una vez que tenemos permisos para autenticar, podemos solicitar una conexion

#figure(
  image("images/exec-9.png"),
  caption: [Solicitud de conexion con usuario y contraseña.]
)

Es importante señalar que, aunque aquí se muestra la contraseña en texto claro, en realidad viaja cifrada.

Sin embargo, resulta algo controvertido enviar la contraseña directamente; sería preferible transmitir solo el hash correspondiente, lo que reduciría el riesgo en caso de que un servidor malicioso almacenara las contraseñas para luego utilizarlas en un ataque de fuerza bruta.

Una vez hecho esto, si la autenticación es exitosa, recibimos varios mensajes del servidor:

+ HostKeys: Autenticación del servidor
+ Confirmación de la apertura del canal

#figure(
  image("images/exec-10.png"),
  caption: [Confirmacion de apertura del canal.]
)

Y estamos en posicion de enviar un comando

== Ejecucion#footnote[RFC4254]

#figure(
  image("images/exec-11.png"),
  caption: [Ejecucion del comando]
)

Enviamos un comando de EXEC con payload `echo hi`

Y recibimos varios mensajes del servidor:
- `SSH2_MSG_CHANNEL_WINDOW_ADJUST`: Incrementando el tamaño maximo de un paquete.
- `SSH2_MSG_CHANNEL_EXTENDED_DATA`: Con informacion del path, y otras variables de entorno
- `SSH2_MSG_CHANNEL_REQUEST`: Pide abrir un canal de comunicacion hacia nosotros
- `SSH2_MSG_CHANNEL_DATA`: Optimisticamente envia la respuesta a nuestra peticion antes que aceptemos abrir el canal.

#figure(
  image("images/exec-12.png"),
  caption: [Respuesta de nuestra ejecucion]
)
]
#pagebreak()

#grid(columns: (1fr, 2fr), column-gutter: 0.5em,[
= Apéndice I

En @handshake-steps se puede observar los pasos y mensajes que intercambian el cliente y servidor durante el handshake SSH para el "happy path", es decir, asumiendo que todo funciona bien y es aceptado.

#bibliography("refs.bib")

Los RFC mencionados tienen links.
],[
#figure(
  // image("./images/ssh-steps.svg", height: 100% - 15em),
  image("./images/ssh-steps.svg"),
  caption: [Pasos del intercambio SSH y ejecución de un comando.]
) <handshake-steps>

])
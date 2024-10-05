#set document(
  author: "Federico Williamson, Leonel Castinelli",
  title: "SSH Handshake",
  date: datetime.today(),
  keywords: ("SSH", "Handshake", "SSH Handshake"),
)
#set text(lang: "es")

#set heading(numbering: "I.")

#show heading.where(level: 1): x => [
  #text(font: "PT Serif", x)
]
#show heading.where(level: 1): x => text(size: 1.5em, x)
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

== ¿Qué es SSH Handshake?

Es un proceso por el cual se establece una conexión segura entre un cliente y un servidor. Se produce tras la primera comunicación con el servidor. Consta de #strong[5 pasos]:

- #strong[Paso 1:] Intercambio de Versiones.
- #strong[Paso 2:] Intercambio de Claves (KEX).
- #strong[Paso 3:] Inicialización de Elliptic Curve Diffie-Hellman (ECDH).
- #strong[Paso 4:] Respuesta de ECDH.
- #strong[Paso 5:] Nuevas Claves (NewKeys).

#pagebreak()
= Intercambio de Versiones.

== Cadena de Version.

@ietfRFC4253

#pagebreak()
#bibliography("refs.bib")
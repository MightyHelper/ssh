#import "@preview/touying:0.5.2": *
#import themes.university: *
#import "@preview/numbly:0.1.0": numbly
//#import "@preview/codelst:2.0.0": sourcecode
#import "@preview/codly:1.0.0": *

#show: codly-init.with()

// Lectura de archivos.
#let main_py = read("../src/main.py")

#codly(
  languages: (
    python: (
      name: "Python",
      color: rgb("#2bce5c")
    ),
  )
)

#show: university-theme.with(
  aspect-ratio: "16-9",
  config-info(
    title: [SSH Handsake],
    subtitle: [Una comunicación segura],
    author: [
      - Federico Williamson
      - Leonel Castinelli
      ],
    //date: datetime.today(),
    institution: [UNCuyo - Facultad de Ingeniería],
    logo: emoji.cat,
  ),
)

#set heading(numbering: numbly("{1}.", default: "1.1"))
#set text(size: 22pt)
#set align(horizon)

// Slide con el titulo
#title-slide()

// Seccion introductoria
= Introducción.

== ¿Qué es SSH Handsake?

#slide[
  Es un proceso por el cual se establece una conexión segura entre un cliente y un servidor. Se produce tras la primera comunicación con el servidor. #pause Consta de #strong[5 pasos]:

#pause 
- #strong[Paso 1:] Intercambio de Versiones.
#pause
- #strong[Paso 2:] Intercambio de Claves (KEX).
#pause
- #strong[Paso 3:] Inicialización de Elliptic Curve Diffie-Hellman (ECDH).
#pause
- #strong[Paso 4:] Respuesta de ECDH.
#pause
- #strong[Paso 5:] Nuevas Claves (NewKeys).
]

== ¿En qué parte opera?

#slide[
  
]

= Intercambio de Versiones.
== Cadena de Versión.

#slide[
  Cada miembro de la comunicación debe tener su propia #strong[Cadena de Versión]. La cual se compone de la siguiente manera:

  #text(size: 25pt, raw("<SSH-protocol-version>-<software-version> <comments>", lang: "python"))
    
  Tanto el #strong[Servidor] como el #strong[Cliente] deben enviar sus Cadenas de Versión, ya que se necesitarán para conformar una conexión segura
]

== Intercambio de Versiones.

#slide(composer: (150pt, auto))[
  #align(horizon)[
  #text(size: 20pt)[
    Ambas versiones se envían codificadas en UTF-8, aquí enviamos la Cadena de Versión al Servidor y leemos la Versión que nos envía:
  ] 
  #codly(enabled: true)
  #codly-range(start: 415, end: 424)
    #text(size: 15pt)[
      ```python
      """ Insertar codigo """
      ```
      //#raw(main_py, block: true, lang:"python")
    ]
  ]
]

= Intercambio de Claves.

== Paquete SSH_MSG_KEX_INIT

#slide[
  #text(size: 22pt)[
    Cada parte de la comunicación envía sus algoritmos criptográficos soportados, en orden de preferencia descendente.
  ]
  #codly-range(start: 261, end: 291)
    #text(size: 25pt)[
      ```python
      """ Insertar codigo """
      ```
      //#raw(main_py, block: true, lang:"python")
    ]
  ]


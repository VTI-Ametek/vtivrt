VTI VRT
=======

vtivrt is a library for decoding/encoding of VITA Radio Transport (VITA 49) data streams, for use with VTI Instruments products.

.. code-block:: python

    >>> import vtivrt
    >>> reader = vtivrt.VtiVrtReader('example.local', 9901)
    >>> packet = reader.read(True)
    >>> packet.stream_id
    257
    >>> packet.timestamp
    Decimal('1646852.220398853')
    >>> packet.data
    [-5.2093963623046875, -5.208981990814209, -5.208486080169678, -5.207897663116455]
    >>> packet.context[0].data.trigger_timestamp
    Decimal('1646852.220391333')

The main classes of interest exposed by vtivrt are:
 * :py:class:`vtivrt.reader.VtiVrtReader` - Connects to a streaming socket, performs handshaking with the server, and reads data.
 * :py:class:`vtivrt.reader.VtiVrtThread` - Creates multiple instances of :py:class:`vtivrt.reader.VtiVrtReader` and collates data from all of them in a background thread.
 * :py:class:`vtivrt.packet.VtiVrtPacket` - Represents one VRT packet, and optionally its associated context packets.

Installing
----------

vtivrt is available on PyPI:

.. code-block:: sh

    $ python -m pip install vtivrt

Documentation
-------------

Full documentation is available at `vtivrt.readthedocs.io <https://vtivrt.readthedocs.io/>`_.

Supported Versions
------------------

vtivrt officially supports Python 3.6+.

Features
--------

* Allows reading and writing VRT data streams to transfer high speed streaming data to and from VTI Instruments products.

#!/usr/bin/env python3
"""Deterministic sanity check for APScream v3.5 PI gains and sign.
A reference *model*, not a compiled/C or hardware test.
"""

def simulate(drift, kp=0.4, ki=0.006, maximum=100):
    fifo = 4096.0
    ema, integral, request = None, 0.0, 0.0
    for _ in range(6000):  # 600 simulated seconds at 10 Hz
        ema = fifo if ema is None else 0.85 * ema + 0.15 * fifo
        error = 4096.0 - ema
        p = kp * error
        candidate = max(-maximum, min(maximum, integral + ki * error * 0.1))
        if not ((p + candidate > maximum and error > 0) or
                (p + candidate < -maximum and error < 0)):
            integral = candidate
        request = max(-maximum, min(maximum, p + integral))
        # Sender follows feedback exactly. Drain is the oscillator's clock.
        fifo += 44100 * 0.1 * (request - drift) / 1_000_000.0
    return fifo, request


def main():
    for drift in (-100, -50, -25, -10, 10, 25, 50, 100):
        fifo, request = simulate(drift)
        assert 3500 < fifo < 4700, (drift, fifo)
        assert abs(request - drift) < 1.5, (drift, request)
        print(f'drift {drift:+d} ppm: requested {request:+.2f} ppm, fifo={fifo:.1f}/8192')
    fifo, request = simulate(500)
    assert request <= 100 and fifo < 0, (request, fifo)
    print('500 ppm exceeds limit and would exhaust FIFO without RESYNC')


if __name__ == '__main__':
    main()

"""Capture authorized IPv4 traffic and pass it to the hybrid IDS engine."""
import argparse
import sys


def main():
    parser = argparse.ArgumentParser(description='Run live packet capture for the Hybrid Network IDS.')
    parser.add_argument('--interface', help='Scapy interface name, copied from --list-interfaces output.')
    parser.add_argument('--list-interfaces', action='store_true', help='List available Scapy interfaces and exit.')
    parser.add_argument('--count', type=int, default=0, help='Stop after this many packets; 0 means keep running.')
    args = parser.parse_args()

    try:
        from scapy.all import get_if_list, sniff
    except ImportError:
        print('Scapy is missing. Install project requirements with: python -m pip install -r requirements.txt')
        return 2

    if args.list_interfaces:
        print('\n'.join(get_if_list()))
        return 0
    if not args.interface:
        parser.error('Provide --interface "NAME" or use --list-interfaces first.')
    if args.count < 0:
        parser.error('--count must be 0 or greater.')

    from ids.database import Database
    from ids.detection import DetectionEngine
    from ids.ml_detector import MLAnomalyDetector
    from ids.packet_parser import parse_packet

    db = Database()
    engine = DetectionEngine(db, MLAnomalyDetector())
    counters = {'captured': 0, 'parsed': 0, 'alerts': 0}

    def handle_packet(packet):
        counters['captured'] += 1
        parsed = parse_packet(packet)
        if parsed is None:
            return
        counters['parsed'] += 1
        alert = engine.process(parsed, simulated=False)
        if alert:
            counters['alerts'] += 1
            print('\n' + '=' * 64)
            print('SECURITY ALERT')
            print(f"Type: {alert['attack_type']} | Risk: {alert['risk_score']}/100 | Severity: {alert['severity']}")
            print(f"Source: {alert['source_ip']} -> Destination: {alert['destination_ip']}")
            print(f"Detection method: {alert['detection_method']}")
            print(alert['details'])
            print('Saved to the dashboard database.')
            print('=' * 64, flush=True)
        elif counters['captured'] % 100 == 0:
            print(f"Captured {counters['captured']} packets; parsed {counters['parsed']}; alerts {counters['alerts']}.", flush=True)

    print(f'Capturing on interface: {args.interface}')
    print('Only capture traffic you are authorized to monitor. Press Ctrl+C to stop.')
    try:
        sniff(iface=args.interface, prn=handle_packet, store=False, count=args.count)
    except PermissionError:
        print('Permission denied. Reopen the terminal with authorized capture privileges and try again.', file=sys.stderr)
        return 1
    except OSError as exc:
        print(f'Capture failed: {exc}. Check the interface name and Npcap installation.', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('\nCapture stopped by user.')
    finally:
        print(f"Summary: captured={counters['captured']}, parsed={counters['parsed']}, alerts={counters['alerts']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

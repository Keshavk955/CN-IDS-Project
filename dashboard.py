import pandas as pd
import plotly.express as px
import streamlit as st

from ids.database import Database
from ids.ml_detector import MLAnomalyDetector
from ids.detection import DetectionEngine
from ids.simulation import generate_demo_packets, generate_benign_burst
from ids.risk_scoring import (
    COMPONENTS,
    DEFAULT_WEIGHTS,
    calculate_contributions,
)

st.set_page_config(
    page_title="Hybrid Network IDS",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Hybrid Network Security Monitoring & IDS")
st.caption(
    "Rule-based detection • Isolation Forest anomaly scoring • "
    "Feedback-guided adaptive risk scoring • SQLite audit trail"
)

db = Database()

if st.session_state.get("demo_message"):
    st.success(st.session_state.pop("demo_message"))

if st.session_state.get("feedback_message"):
    st.success(st.session_state.pop("feedback_message"))

with st.sidebar:
    st.header("Controls")
    st.write(
        "Demo mode uses synthetic packets only. "
        "It does not generate network traffic."
    )

    if st.button("▶ Run safe demo", use_container_width=True):
        engine = DetectionEngine(db, MLAnomalyDetector())
        alerts_created = 0

        for packet in generate_demo_packets():
            alerts_created += bool(
                engine.process(packet, simulated=True)
            )

        st.session_state["demo_message"] = (
            f"Demo processed 52 synthetic packets; "
            f"{alerts_created} new alerts created."
        )
        st.rerun()

    if st.button(
        "Run benign-burst feedback example",
        use_container_width=True,
    ):
        engine = DetectionEngine(db, MLAnomalyDetector())
        before = len(db.get_alerts(limit=1000))

        for packet in generate_benign_burst():
            engine.process(packet, simulated=True)

        after = len(db.get_alerts(limit=1000))

        st.session_state["demo_message"] = (
            "Processed 45 synthetic benign high-volume packets; "
            f"{max(0, after - before)} alert(s) created. "
            "This scenario is intentionally benign and demonstrates "
            "a possible false positive."
        )
        st.rerun()

    if st.button("↻ Refresh dashboard", use_container_width=True):
        st.rerun()

    if st.button(
        "Clear simulated traffic and demo alerts",
        use_container_width=True,
    ):
        db.clear_demo_data()
        st.session_state["demo_message"] = (
            "Simulated traffic and TEST-NET demo alerts cleared. "
            "Feedback-adjusted weights were preserved."
        )
        st.rerun()

    if st.button("Reset adaptive weights", use_container_width=True):
        db.reset_weights()
        st.session_state["demo_message"] = (
            "Feedback-adjusted weights for all alert types were "
            "reset to the 35/35/20/10 base values. "
            "The feedback audit history was preserved."
        )
        st.rerun()

    st.divider()
    st.markdown("**Live capture**")
    st.code(
        'python run_live.py --list-interfaces\n'
        'python run_live.py --interface "YOUR_INTERFACE"'
    )
    st.caption(
        "Run live capture in a separate terminal with Scapy, "
        "Npcap and authorized capture permissions."
    )

    st.divider()
    st.markdown("**Base component weights**")

    base_weights = db.get_weights()

    base_table = pd.DataFrame([
        {
            "Component": name.title(),
            "Weight": f"{weight:.1%}",
        }
        for name, weight in base_weights.items()
    ])

    st.dataframe(
        base_table,
        hide_index=True,
        use_container_width=True,
    )

    pattern_rows = db.get_pattern_weights()

    if pattern_rows:
        st.markdown("**Feedback-adjusted weights by alert type**")
        display_pattern_rows = []

        for row in pattern_rows:
            display_pattern_rows.append({
                "Alert type": row["attack_type"],
                "Reviews": row["feedback_count"],
                "True +": row["true_positive_count"],
                "False +": row["false_positive_count"],
                "Rule": f"{row['rule']:.1%}",
                "ML": f"{row['ml']:.1%}",
                "Anomaly": f"{row['anomaly']:.1%}",
                "History": f"{row['historical']:.1%}",
            })

        st.dataframe(
            pd.DataFrame(display_pattern_rows),
            hide_index=True,
            use_container_width=True,
        )

    counts = db.get_feedback_counts()

    st.caption(
        f"Feedback recorded: {counts['TRUE_POSITIVE']} true positive, "
        f"{counts['FALSE_POSITIVE']} false positive. "
        "Weights are learned separately for each alert type."
    )

alerts = pd.DataFrame(db.get_alerts(limit=1000))
traffic = pd.DataFrame(db.get_traffic(limit=3000))

if traffic.empty:
    st.info(
        "No traffic records yet. Click **Run safe demo** or start "
        "run_live.py to populate the dashboard."
    )

    traffic = pd.DataFrame(columns=[
        "timestamp",
        "source_ip",
        "destination_ip",
        "protocol",
        "packet_size",
        "is_simulated",
    ])

if alerts.empty:
    alerts = pd.DataFrame(columns=[
        "id",
        "timestamp",
        "source_ip",
        "destination_ip",
        "attack_type",
        "severity",
        "risk_score",
        "detection_method",
        "details",
        "acknowledged",
        "feedback_label",
    ])

c1, c2, c3, c4 = st.columns(4)

c1.metric("Packets recorded", len(traffic))
c2.metric("Security alerts", len(alerts))

c3.metric(
    "High / critical",
    int(alerts["severity"].isin(["HIGH", "CRITICAL"]).sum())
    if not alerts.empty else 0,
)

c4.metric(
    "Average alert risk",
    f"{alerts['risk_score'].mean():.1f}/100"
    if not alerts.empty else "—",
)

st.divider()

left, right = st.columns(2)

with left:
    st.subheader("Traffic by protocol")

    if not traffic.empty:
        st.plotly_chart(
            px.pie(
                traffic,
                names="protocol",
                title="Protocol distribution",
            ),
            use_container_width=True,
        )
    else:
        st.write("No traffic data yet.")

with right:
    st.subheader("Alerts by severity")

    if not alerts.empty:
        st.plotly_chart(
            px.histogram(
                alerts,
                x="severity",
                category_orders={
                    "severity": [
                        "SAFE",
                        "LOW",
                        "MEDIUM",
                        "HIGH",
                        "CRITICAL",
                    ]
                },
                title="Severity distribution",
            ),
            use_container_width=True,
        )
    else:
        st.write("No alerts yet.")

st.subheader("Recent security alerts")

if not alerts.empty:
    columns = [
        "id",
        "timestamp",
        "source_ip",
        "destination_ip",
        "attack_type",
        "severity",
        "risk_score",
        "detection_method",
        "feedback_label",
        "acknowledged",
        "is_simulated",
    ]

    show = alerts[[c for c in columns if c in alerts.columns]].copy()

    st.dataframe(
        show,
        use_container_width=True,
        hide_index=True,
    )

    pending = alerts[
        alerts["feedback_label"].isna()
        | (alerts["feedback_label"] == "")
    ]

    component_columns = [
        f"{name}_score" for name in COMPONENTS
    ]

    if all(col in pending.columns for col in component_columns):
        has_components = (
            pending[component_columns].fillna(0).sum(axis=1) > 0
        )

        legacy_count = int((
            ~has_components
            & (pending["risk_score"].fillna(0) > 0)
        ).sum())

        pending = pending[has_components]

        if legacy_count:
            st.caption(
                f"{legacy_count} older alert(s) lack stored component "
                "scores and are excluded from adaptive feedback. "
                "Clear old demo data and rerun the demo to create "
                "fully explainable alerts."
            )

    if not pending.empty:
        st.markdown("**Review an alert**")

        selected_id = st.selectbox(
            "Choose an unreviewed alert",
            pending["id"].tolist(),
            format_func=lambda alert_id: (
                f"#{alert_id} — "
                f"{pending.loc[pending['id'] == alert_id, 'attack_type'].iloc[0]} "
                f"(risk "
                f"{pending.loc[pending['id'] == alert_id, 'risk_score'].iloc[0]})"
            ),
        )

        fb1, fb2 = st.columns(2)

        with fb1:
            if st.button(
                "Confirm attack (true positive)",
                use_container_width=True,
            ):
                try:
                    selected_type = str(
                        pending.loc[
                            pending["id"] == selected_id,
                            "attack_type",
                        ].iloc[0]
                    )

                    old, new = db.apply_feedback(
                        selected_id,
                        "TRUE_POSITIVE",
                    )

                    changed = ", ".join(
                        f"{name}: {old[name]:.1%} → {new[name]:.1%}"
                        for name in COMPONENTS
                    )

                    st.session_state["feedback_message"] = (
                        f"Feedback saved for alert #{selected_id} "
                        f"({selected_type}). Updated weights for this "
                        f"alert type only — {changed}. Other alert "
                        "types retain their own weights."
                    )

                    st.rerun()

                except ValueError as exc:
                    st.error(str(exc))

        with fb2:
            if st.button(
                "Mark as false positive",
                use_container_width=True,
            ):
                try:
                    selected_type = str(
                        pending.loc[
                            pending["id"] == selected_id,
                            "attack_type",
                        ].iloc[0]
                    )

                    old, new = db.apply_feedback(
                        selected_id,
                        "FALSE_POSITIVE",
                    )

                    changed = ", ".join(
                        f"{name}: {old[name]:.1%} → {new[name]:.1%}"
                        for name in COMPONENTS
                    )

                    st.session_state["feedback_message"] = (
                        f"Feedback saved for alert #{selected_id} "
                        f"({selected_type}). Updated weights for this "
                        f"alert type only — {changed}. Other alert "
                        "types retain their own weights."
                    )

                    st.rerun()

                except ValueError as exc:
                    st.error(str(exc))

        st.caption(
            "Use true positive only for a confirmed attack and false "
            "positive only for benign traffic. Feedback updates weights "
            "for that alert type only; other alert types are not changed. "
            "Past scores and their recorded weights are preserved."
        )

    else:
        st.caption(
            "All currently displayed alerts have feedback labels. "
            "New alerts can be reviewed when they arrive."
        )

    pending_ack = alerts[alerts["acknowledged"] == 0]

    if not pending_ack.empty:
        selected_ack = st.selectbox(
            "Acknowledge an alert (administrative status only)",
            pending_ack["id"].tolist(),
            key="ack_select",
        )

        if st.button("Mark selected alert acknowledged"):
            db.acknowledge(selected_ack)

            st.session_state["feedback_message"] = (
                f"Alert #{selected_ack} acknowledged. "
                "This does not change feedback-adjusted weights."
            )

            st.rerun()

else:
    st.write("No alerts recorded yet.")

with st.expander("Explain a risk score"):
    if not alerts.empty:
        selected_explain_id = st.selectbox(
            "Choose an alert to explain",
            alerts["id"].tolist(),
            key="explain_select",
        )

        selected_row = alerts.loc[
            alerts["id"] == selected_explain_id
        ].iloc[0]

        required_columns = [
            "rule_score",
            "ml_score",
            "anomaly_score",
            "historical_score",
            "rule_weight",
            "ml_weight",
            "anomaly_weight",
            "historical_weight",
        ]

        if all(
            col in alerts.columns
            for col in required_columns
        ):
            scores = {
                name: float(selected_row[f"{name}_score"] or 0)
                for name in COMPONENTS
            }

            weights = {
                name: float(selected_row[f"{name}_weight"] or 0)
                for name in COMPONENTS
            }

            if (
                float(selected_row["risk_score"]) > 0
                and sum(scores.values()) == 0
            ):
                st.info(
                    "This is an older alert. Its component scores "
                    "were not stored, so a breakdown is unavailable. "
                    "New alerts include one."
                )

            else:
                contributions = calculate_contributions(
                    scores,
                    weights,
                )

                breakdown = pd.DataFrame([
                    {
                        "Component": name.title(),
                        "Component score": scores[name],
                        "Weight at alert time": f"{weights[name]:.1%}",
                        "Contribution to risk": contributions[name],
                    }
                    for name in COMPONENTS
                ])

                st.dataframe(
                    breakdown,
                    hide_index=True,
                    use_container_width=True,
                )

                st.metric(
                    "Stored risk score",
                    f"{float(selected_row['risk_score']):.2f}/100",
                )

                st.caption(
                    "Contribution = component score × weight recorded "
                    "when the alert was created. Later feedback only "
                    "affects future alerts."
                )

                st.write(
                    "Detection details:",
                    selected_row.get("details", ""),
                )

        else:
            st.info(
                "Component score fields are not available "
                "in this database yet."
            )

    else:
        st.write(
            "Generate a demo or capture traffic before explaining an alert."
        )

st.subheader("Recent traffic records")

if not traffic.empty:
    display_cols = [
        "timestamp",
        "source_ip",
        "destination_ip",
        "protocol",
        "source_port",
        "destination_port",
        "packet_size",
        "flags",
        "is_simulated",
    ]

    st.dataframe(
        traffic[
            [col for col in display_cols if col in traffic.columns]
        ].head(200),
        use_container_width=True,
        hide_index=True,
    )

with st.expander("How feedback-guided adaptive risk scoring works"):
    st.markdown("""
    The base component weights are **rule 35%, ML 35%, anomaly 20%,
    historical 10%**.

    Each alert type has its own feedback-adjusted weight set. When an
    analyst labels a port-scan alert, only future port-scan alerts use
    those updated weights; ICMP or high-packet-rate alerts do not inherit
    that adjustment.

    For a confirmed attack, relatively high component scores gain weight.
    For a false positive, relatively high component scores lose weight.
    Weights are bounded, normalized to sum to 100%, and stored in SQLite.

    This is a transparent feedback-guided heuristic, not a calibrated
    probability or proof of better real-world accuracy. Source reputation
    separately uses exponential time decay so older alerts gradually
    lose influence.
    """)

st.caption(
    "For educational/research use. Detection thresholds require tuning "
    "and should not be treated as proof of an attack. The Isolation "
    "Forest currently uses a synthetic baseline and requires evaluation "
    "against labelled traffic."
)
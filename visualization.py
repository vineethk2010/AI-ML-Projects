#!/usr/bin/env python3
"""
Module Docstring
"""

# visualization.py
import pandas as pd
import plotly.express as px
import streamlit as st


def create_visualizations(df: pd.DataFrame):
    """Create and display visualizations for the network traffic data."""
    if len(df) > 0:
        # Protocol distribution
        protocol_counts = df['protocol'].value_counts()
        fig_protocol = px.pie(
            values=protocol_counts.values,
            names=protocol_counts.index,
            title="Protocol Distribution"
        )
        st.plotly_chart(fig_protocol, use_container_width=True)

        # Packets timeline
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df_grouped = df.groupby(df['timestamp'].dt.floor('S')).size()
        fig_timeline = px.line(
            x=df_grouped.index,
            y=df_grouped.values,
            title="Packets per Second"
        )
        st.plotly_chart(fig_timeline, use_container_width=True)

        # Top source IPs
        top_sources = df['source'].value_counts().head(10)
        fig_sources = px.bar(
            x=top_sources.index,
            y=top_sources.values,
            title="Top Source IP Addresses"
        )
        st.plotly_chart(fig_sources, use_container_width=True)



def pred_visuals(results):
    st.subheader("Predicted Label Distribution")
    fig = px.bar(
        results.melt(id_vars=['label'], value_vars=['Predicted_Label']),
        x='value', color='variable',
        # title="Distribution of Labels",
        labels={'value': 'Labels', 'variable': 'Type'},
        barmode='group'
    )
    st.plotly_chart(fig, use_container_width=True)

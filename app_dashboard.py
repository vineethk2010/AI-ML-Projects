#!/usr/bin/env python3
"""
Module Docstring
"""

__author__ = "Vineeth Krishnankutty"
__version__ = "0.1.0"
__license__ = "MIT"

#!/usr/bin/env python3
"""
Main Application for Network Traffic Analysis
"""

import streamlit as st
import pandas as pd
import time
from capture import start_packet_capture
from visualization import create_visualizations, pred_visuals
from prediction import predict_on_holdout_dataset

# st.set_page_config(page_title="Network Traffic Analysis", layout="wide")

def main():
    st.title("Real-time Network Traffic Analysis")

    # Initialize packet processor in session state
    if 'processor' not in st.session_state:
        st.session_state.processor = start_packet_capture()
        st.session_state.start_time = time.time()

    # Create dashboard layout
    col1, col2 = st.columns(2)

    # Get current data
    df = st.session_state.processor.get_dataframe()

    # Display metrics
    with col1:
        st.metric("Total Packets", len(df))
    with col2:
        duration = time.time() - st.session_state.start_time
        st.metric("Capture Duration", f"{duration:.2f}s")

    # Display visualizations
    create_visualizations(df)

    # Display recent packets
    st.subheader("Recent Packets")
    if len(df) > 0:
        st.dataframe(
            df.tail(10)[['timestamp', 'source', 'destination', 'protocol', 'size']],
            use_container_width=True
        )

    # Add refresh button
    if st.button('Refresh Data'):
        st.rerun()

    st.subheader("Prediction")
    holdout_dataset_path = './Holdout.csv'
    # uploaded_file = pd.read_csv(holdout_dataset_path)
    if holdout_dataset_path is not None:
        # Perform prediction
        results = predict_on_holdout_dataset(holdout_dataset_path)
        # st.write("Prediction Results:")
        pred_visuals(results)
        # st.dataframe(results[['label', 'Predicted_Label']])

    # Auto refresh
    # time.sleep(10)
    # st.rerun()



if __name__ == "__main__":
    main()


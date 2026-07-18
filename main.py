import bcrypt
import streamlit as st
import pandas as pd
import datetime # Built-in library to work with dates and timestamps 
import plotly.express as px #to use plotly for the visual aids piechart,barchart and histogram
from google import genai#use for the gemini ai 

# PACKAGE IMPORTS
from app_model.db import get_connection
from app_model.schema import create_user_table
from app_model.user import add_user, get_user,generate_hash,is_valid_hash,sanitize_username
#used for the account lockout policy
from app_model.user import update_lockout, reset_lockout
#used for generate password and check password strenght
from app_model.password_utils import generate_secure_password, is_strong_password
#used for the admin page choice
from app_model.Admin import render_admin_panel


# Importing data modules
from app_model.cyber_incidents import migrate_cyber_incidents, get_all_cyber_incidents
from app_model.it_tickets import migrate_it_tickets, get_all_it_tickets
from app_model.metadas import migrate_metadata, get_all_metadata



#STREAMLIT INITIALIZATION
st.set_page_config(
    page_title="Multi-Domain Intelligence Platform", 
    page_icon="🛡️", 
    layout="wide"
)

#ADMIN credentials 
#plaintext for the user name
ADMIN_USERNAME = "ben"
#hashed password generated from the Admin_PWHash.py
ADMIN_HASHED_PW = b'$2b$12$Hbl1uj8f4tWDMaVbFRMKBuNk1WCX06ynNWcU7uA9e7Q1jd1YTBgp.'


# Database Link 
conn = get_connection()
create_user_table(conn)
migrate_cyber_incidents(conn)
migrate_it_tickets(conn)
migrate_metadata(conn)

# Session Management Setup
if "logged_in" not in st.session_state: st.session_state.logged_in = False #Check whether logged it 
#setting empty variable so when login it can be hled there 
if "username" not in st.session_state: st.session_state.username = None 
#setting empty variable so it track (admin or user)
if "role" not in st.session_state: st.session_state.role = None



 
#LAZY LOADING LAUNCH FRAGMENTS 
#using st.fragments to enable reruning without reloading the whole page
#Three independent fragments section would be created respectively here 

#NOTE: The sorting logic matches for all 3 fragments

#Using @st.fragment to break heavy data tables into independent components. 
@st.fragment
def render_metadata_lazy():
    st.subheader("📊 Platform Dataset Infrastructure")#subheader
    df_meta = get_all_metadata(conn)#getting the data from the database
    
    ## Creates an options list starting with "All", followed by sorted, unique usernames if the column exists
    # otherwise defaults to just ["All"]
    uploader_options = ["All"] + sorted(list(df_meta["uploaded_by"].unique())) if "uploaded_by" in df_meta.columns else ["All"]
    #a dropdown menu using options list and stores the user's selected choice into 'selected_uploader'
    selected_uploader = st.selectbox("Filter by Staff Role 👥:", options=uploader_options)
    
    # Creates a copy of the df to prevent modifications from altering or breaking the original database records
    df_filtered = df_meta.copy()

    #executes only if a specific staff member is picked and the filtering column is confirmed to exist
    if selected_uploader != "All" and "uploaded_by" in df_filtered.columns:
        ## Filters the df in place to keep only the rows where the uploader matches the selection from the dropdown
        df_filtered = df_filtered[df_filtered["uploaded_by"] == selected_uploader]
        
    st.caption(f"Lazily parsed: {len(df_filtered)} files matched.")#a caption shown to user
    st.dataframe(df_filtered, use_container_width='stretch')#display filtered table hence strech horizantally to autofit width



@st.fragment
def render_cyber_incidents_lazy():
    st.subheader("🌐 Cyber Incidents Monitoring Log")#subheader
    df_incidents = get_all_cyber_incidents(conn)#get data from db
    
    #Split the layout into 3 parts 
    col1, col2, col3 = st.columns(3)
    #hence it generates sorted unique choices and renders the dropdown filter menus inside each column layout 
    with col1:
        sev_options = ["All"] + sorted(list(df_incidents["severity"].unique())) if "severity" in df_incidents.columns else ["All"]
        selected_sev = st.selectbox("Filter Severity⚠️ :", options=sev_options)
    with col2:
        cat_options = ["All"] + sorted(list(df_incidents["category"].unique())) if "category" in df_incidents.columns else ["All"]
        selected_cat = st.selectbox("Filter Category❔:", options=cat_options)
    with col3:
        stat_options = ["All"] + sorted(list(df_incidents["status"].unique())) if "status" in df_incidents.columns else ["All"]
        selected_stat = st.selectbox("Filter Status❗:", options=stat_options)

    df_filtered = df_incidents.copy()# a copy is created 
    #checks each dropdown state and updates the df 'in place' to keep matching records
    #Every time a line runs, it looks at df_filtered, erases what doesn't match the dropdown selection, 
    #and saves the new, smaller list right back into the df_filtered variable
    if selected_sev != "All": df_filtered = df_filtered[df_filtered["severity"] == selected_sev]
    if selected_cat != "All": df_filtered = df_filtered[df_filtered["category"] == selected_cat]
    if selected_stat != "All": df_filtered = df_filtered[df_filtered["status"] == selected_stat] 
    
    st.dataframe(df_filtered, use_container_width='stretch')#dsiplay tbale and autofit accordingly 
    

    #VISUAL DISPLAY 
    # Ensure that we only attempt to generate visual metrics if the filtered data actually exists
    if not df_filtered.empty:
        # HEADER: Threat Landscape Analysis
        st.markdown("---")
        st.markdown("### 📊 Threat Landscape Analysis")
        plot_df = df_filtered.copy() ## Create copy of the filtered df to avoid modifying the original data state

        #preparing data fr the barchar and piechart
        # Use Pandas '.value_counts()' to count how many times each severity tier appears.
        # '.reset_index()' converts the resulting Series back into a structured DataFrame
       
        #BARCHART (Severity) 
        severity_df = plot_df["severity"].value_counts().reset_index()
        # Rename the df columns so that Plotly can read and label them clearly.
        severity_df.columns = ["Severity", "Incident Count"]


        #  PIE CHART (Incident categories)
        cat_df = plot_df["category"].value_counts().reset_index()
        #rename the columns so the piechart knows what to display
        cat_df.columns = ["Incident Type", "Count"]

        

        # CHART RENDERING & LAYOUT STYLING
        # Split the screen into two equal columns to display the charts side-by-side
        col1, col2 = st.columns(2)

        # COL1:SEVERITY BAR CHART
        with col1:
            # Create a Plotly Express Barchart our grouped severity DataFrame.
            fig_bar = px.bar(
                severity_df,
                x="Severity",                    # Categories (Low, Medium, Critical) on X-axis
                y="Incident Count",             # Quantitative counts on the Y-axis
                title="Incidents by Severity Level", # The prominent header of our visual chart
                color_discrete_sequence=["#FF4B4B"] # Theme matching: keeps the warning-red color brand
            )
            
            # Style the Plotly figure configuration to blend with the Streamlit Dark Theme.
            fig_bar.update_layout(
                # Sets transparent canvas backgrounds 
                # rgb (00000)makes the frame transparent
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                
                # Formats the text colors to a light gray for readability
                font_color="#e0e0e0",
                title_font_size=16,
                
                #turn on light backgroind grid line of colour grey 
                xaxis=dict(showgrid=True, gridcolor="#2c2c2c"),
                yaxis=dict(showgrid=True, gridcolor="#2c2c2c")
            )
            # Plotly barchart is drawn and fit to coloumn width
            st.plotly_chart(fig_bar, use_container_width=True)


        # COL2: PIE CHART
        with col2:
            # create a Pie Chart representing relative incident volumes
            fig_pie = px.pie(
                cat_df,
                names="Incident Type",#set the label of each pie slice
                values="Count",#set the size based on incident count
                title="Incident Category Distribution",#title od piechart
                color_discrete_sequence=px.colors.sequential.Reds_r # apply gradient of red to the slices
            )
            # Style the pie chart to match dark theme settings
            fig_pie.update_layout(
                # Sets transparent canvas backgrounds 
                # rgb (00000)makes the frame transparent
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#e0e0e0",
                title_font_size=16,
                showlegend=True,
                # Makes the legend lay flat (horizontal) 
                #centers it right beneath the graph
                legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5)
            )
            # piechart is drawn and fit 
            st.plotly_chart(fig_pie, use_container_width=True)
    



@st.fragment
def render_it_tickets_lazy():
    st.subheader("🎫 IT Operational Service Requests")#subheader
    df_tickets = get_all_it_tickets(conn)#get data from db

    #split layout in 2 parts 
    col1,col2 = st.columns(2)
    #it generates sorted unique choices and renders the dropdown filter menus inside each column layout 
    with col1:
        status_options = ["All"] + sorted(list(df_tickets["status"].unique())) if "status" in df_tickets.columns else ["All"]
        selected_status = st.selectbox("Filter Status❗:", options=status_options)

    with col2:
        priority_options = ["All"] + sorted(list(df_tickets["priority"].unique())) if "priority" in df_tickets.columns else ["All"]
        selected_priority = st.selectbox("Filter Priority📊:", options=priority_options)
        
    df_filtered = df_tickets.copy()#copy created 
    #checks each dropdown state and updates the df 'in place' to keep matching records
    #Every time a line runs, it looks at df_filtered, erases what doesn't match the dropdown selection, 
    #and saves the new, smaller list right back into the df_filtered variable
    if selected_status != "All": df_filtered = df_filtered[df_filtered["status"] == selected_status]
    if selected_priority != "All": df_filtered = df_filtered[df_filtered["priority"] == selected_priority]
    st.dataframe(df_filtered, use_container_width='stretch') #display table and autofit accordingly


    # Verify that the filtered dataframe is not empty before drawing charts
    if not df_filtered.empty:
        # HEADER: IT Operations Metrics
        st.markdown("---")
        st.markdown("### 📊 IT Operations Metrics")#header part before the visual displays

        #Preparing the donut chart datat
        # Use Pandas '.value_counts()' to count how many times each severity tier appears.
        # '.reset_index()' converts the resulting Series back into a structured df
        priority_df = df_filtered["priority"].value_counts().reset_index()
        #rename the columns so the piechart knows what to display
        priority_df.columns = ["Priority", "Count"]

    
         #CHART RENDERING & LAYOUT STYLING
        # Partition the UI to host two distinct operational graphs
        col1, col2 = st.columns(2)

        # COLUMN 1: DONUT CHART 
        with col1:
            # Build a modern donut visual representing system emergency levels
            fig_donut = px.pie(
                priority_df,
                names="Priority", #set what label each slice represent 
                values="Count", #set the size of the slice per the total count of ticket
                hole=0.5, # create the hole in middle that create the donut form 
                title="Ticket Priority Breakdown",
                color="Priority",#specific colours goes to specifc priority levels
                # Explicit color coding based on incident response severity protocols
                color_discrete_map={"Critical": "#D62728", "High": "#FF7F0E", "Medium": "#1F77B4"}
            )
            # Set custom dark themes with transparent backdrops
            fig_donut.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#e0e0e0",#the colour of the text 
                title_font_size=16,
                showlegend=True,
                #Makes the legend lay flat (horizontal) 
                #centers it right beneath the graph
                legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5)
            )
            # Display the donut chart in the left half of the display module
            st.plotly_chart(fig_donut, use_container_width=True)

        # COLUMN 2: HISTOGRAM
        with col2:
            # Build a histogram showing ticket resolution times
            fig_hist = px.histogram(
                df_filtered,
                x="resolution_time_hours", # xaxis value
                nbins=15,# Limits the chart to a maximum of 15 vertical bars
                title="Resolution Time Spread (Hours)",
                color_discrete_sequence=["#9467BD"]   # bar of colour violet purplish
            )
            # Apply uniform transparency and dark-background labeling rules
            fig_hist.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#e0e0e0",
                title_font_size=16,
                #Labels the axes clearly and adds gridlines only on the horizontal axis
                xaxis=dict(title="Hours to Resolve", showgrid=False),
                yaxis=dict(title="Ticket Count", showgrid=True, gridcolor="#2c2c2c")
            )
            # Render the frequency distribution plot in the UI
            st.plotly_chart(fig_hist, use_container_width=True)





#THE MAIN 
def main():
    st.title("🛡️ Multi-Domain Intelligence Platform")#app title 
    
    #check if user is not logged in yet
    if not st.session_state.logged_in:
        st.subheader("🔑 Authentication Portal")
        tab1, tab2, tab3 = st.tabs(["Sign In", "Register Account", "Forgot Password"])#split into 3 tabs 
        
        # TAB 1: USER SIGN IN
        with tab1:
            #SO here in the login from their is username, password to input
            #and verify credentials button
            with st.form("login_form"):
                user_input = st.text_input("Username")
                pass_input = st.text_input("Password", type="password")
                btn_login = st.form_submit_button("Verify Credentials")
                
                if btn_login:
                    #clean the username name input
                    cleaned_username = sanitize_username(user_input)
                    if cleaned_username == ADMIN_USERNAME: 
                        # Convert the user's password input string to bytes
                        password_bytes = pass_input.encode('utf-8')
                        
                        # Cryptographically verify the password against the hardcoded admin salted hash
                        if bcrypt.checkpw(password_bytes, ADMIN_HASHED_PW):
                            # logged in as admin
                            st.session_state.logged_in = True
                            st.session_state.username = "ben"
                            st.session_state.role = "Admin"  # Role:Admin
                            st.success("🔒 Secure Session Initialized: Welcome, Administrator Ben!")
                            st.rerun()#refresh app to open admin page
                        else:
                            st.error("Access Refused: Invalid credentials match profiles.")
                    
                    # check normal users in the db
                    else:
                        # Fetch the user's record from SQL return the cleaned username from db
                        user_record = get_user(conn, cleaned_username)
                        
                        if user_record:
                            # Extract attempts and lockout from their exact index positions:
                            # (Index 6 is login_attempts, Index 7 is lockout_until)
                            attempts = user_record[6]
                            lockout_until_str = user_record[7]
                            
                            # CHECK FOR ACTIVE LOCKOUT
                            if lockout_until_str:
                                #convert the stored lcokout string into a datetime object 
                                lockout_time = datetime.datetime.fromisoformat(lockout_until_str)
                                current_time = datetime.datetime.now()
                                
                                #check if still in lockout time 
                                if current_time < lockout_time:
                                    #calculate and display how many seconds left until lockout 
                                    seconds_left = int((lockout_time - current_time).total_seconds())
                                    st.error(f"❌ Account locked. Try again in {seconds_left} seconds.")
                                    st.stop()
                                else:
                                    # Cooldown time has pass hence Reset lockout tracking in DB and reset local variable
                                    reset_lockout(conn, cleaned_username)
                                    attempts = 0

                            # 4. VERIFY PASSWORD USING BCRYPT (Index 2 is password_hash)
                            # We encode both strings to bytes so bcrypt can compare them
                            input_password_bytes = pass_input.encode('utf-8')
                            stored_hash_bytes = user_record[2].encode('utf-8')
                            
                            # This compares the hash
                            is_password_correct = bcrypt.checkpw(input_password_bytes, stored_hash_bytes)
                            
                            if is_password_correct:
                                # SUCCESS: Login allowed, Clear the failed attempts database record
                                reset_lockout(conn, cleaned_username)
                                
                                st.session_state.logged_in = True
                                st.session_state.username = cleaned_username
                                st.session_state.role = user_record[3]  # Index 3 is 'role'
                                st.success(f"🔓 Welcome back, {cleaned_username}!")
                                st.rerun()
                            else:
                                #Wrong password then Increment attempt counter
                                new_attempts = attempts + 1
                                
                                if new_attempts >= 3: #have 3 tries to attempt
                                    # Lockout for 5 minutes
                                    cooldown_period = datetime.timedelta(minutes=5)
                                    lockout_expiry = datetime.datetime.now() + cooldown_period
                                    
                                    update_lockout(conn, cleaned_username, new_attempts, lockout_expiry)
                                    st.error("❌ Too many failed attempts! Your account has been temporarily locked for 5 minutes.")
                                else:
                                    # Record the attempt and show remaining tries
                                    update_lockout(conn, cleaned_username, new_attempts, None)
                                    st.warning(f"⚠️ Incorrect password. You have {3 - new_attempts} attempts remaining.")
                        else:
                            st.error("❌ Username does not exist in our systems.")
                            

                # TAB 2: UNIQUE ACCOUNT REGISTRATIO
                with tab2:
                    st.markdown("### Create New Identity Profiles")#form header 
                    
                    # Password Generator
                    if st.button("🔑 Generate Strong Password"):
                        gen_pass = generate_secure_password()
                        st.code(gen_pass, language="text")# display it in a box
                        

                    with st.form("register_form"): #form block with several user registration details
                        new_user = st.text_input("Choose Unique Username")
                        new_pass = st.text_input("Choose Password", type="password")
                        confirm_pass = st.text_input("Confirm Password", type="password")
                        
                        # Security challenge questions collected during registration
                        reg_car = st.text_input("Security Answer 1: What is your dream car?")
                        reg_crush = st.text_input("Security Answer 2: What is the name of your crush?")
                        
                        btn_reg = st.form_submit_button("Submit") #submit button
                        
                        if btn_reg:
                            # clean the input and check if it already exists
                            cleaned_new_user = sanitize_username(new_user)
                            existing_account = get_user(conn, cleaned_new_user)
                            
                            if len(cleaned_new_user.strip()) < 3:#check if it has at least 3 character
                                st.warning("Username must contain at least 3 characters.")
                            elif existing_account is not None:
                                st.error("❌ Integrity Error: This username is already registered.")
                            elif new_pass != confirm_pass:#if password and confrirm password donot match cannot proceed
                                st.error("❌ Mismatch: Password confirmation strings do not track matching characters.")
                            else:
                                #check if password meet all the criteria for strong password
                                is_valid, missing_reqs = is_strong_password(new_pass)
                                if not is_valid:
                                    st.error(f"❌ Weak Password Baseline requirements missing: {missing_reqs}")
                                else:
                                    #hash the passwrod 
                                    hashed_val = generate_hash(new_pass.strip())

                                    #hash both security answers!
                                    hashed_car = generate_hash(reg_car.strip().lower())
                                    hashed_crush = generate_hash(reg_crush.strip().lower())

                                    # saving the data db
                                    success = add_user(
                                        conn, 
                                        cleaned_new_user.strip(), 
                                        hashed_val, 
                                        hashed_car, 
                                        hashed_crush
                                    )
                                    if success:
                                        st.success("Registered Sucessfully. Proceed to Sign In.")
                                    else:
                                        st.error("Failed to registered")


        # TAB 3: PASSWORD RECOVERY
        with tab3:
            # Display a clean title for the password recovery form
            st.markdown("### 🔒 Password Recovery")
            
            # Create the Streamlit form container
            with st.form("recovery_form"):
                # Input field for the user to provide their username
                recovery_user = st.text_input("Username")
                
                st.markdown("---")
                st.markdown("#### 🧬 Identity Verification Challenges")
                # Input fields for the security challenge answers (kept secure and hidden)
                answer_car = st.text_input("Security Question 1: What is your dream car?")
                answer_crush = st.text_input("Security Question 2: What is the name of your crush?")
                
                st.markdown("---")
                st.markdown("#### 🔑 Choose New Credentials")
                # Secure password input fields (masks characters with dots)
                recovery_pass = st.text_input("New Password", type="password")
                confirm_pass = st.text_input("Confirm New Password", type="password")
                
                # Form submission button
                btn_recover = st.form_submit_button("Confirm")
                
                #ON SUBMIT: FORM VALIDATION
                if btn_recover:
                    # Clean the inputs by stripping leading/trailing whitespace
                    # and make security answers lowercase
                    clean_user = recovery_user.strip()
                    clean_car = answer_car.strip().lower()
                    clean_crush = answer_crush.strip().lower()
                    
                    # Look up the user in the database
                    account_match = get_user(conn, clean_user)
                    
                    # Check if the user exists in the database
                    if not account_match:
                        st.error("❌ Validation Error: Username not found")
                    
                    # Check if any fields were left empty
                    elif not clean_car or not clean_crush or not recovery_pass:
                        st.warning(" All fields must be filled out")
                        
                    # Check if the new passwords match each other
                    elif recovery_pass != confirm_pass:
                        st.error("❌ Password Mismatch ")
                        
                    
                    else:
                        # (Index 4 is 'dream_car' hash, Index 5 is 'crush_name' hash)
                        #check whether the security answers match the db hashes 
                        db_saved_car_hash = account_match[4]
                        db_saved_crush_hash = account_match[5]
                        
                        # Use the verify_hash function to check input against the secure database hash.
                        # (Returns True if they match, False if not)
                        car_is_correct = is_valid_hash(clean_car, db_saved_car_hash)
                        crush_is_correct = is_valid_hash(clean_crush, db_saved_crush_hash)
                        
                        # If both security ans match secure hashes perfectly:
                        if car_is_correct and crush_is_correct:
                            # Verify if the proposed new password meets the requirement 
                            is_valid, missing_reqs = is_strong_password(recovery_pass)
                            
                            if not is_valid:
                                st.error(f"❌ Weak Password: Requirements missing: {missing_reqs}")
                            else:
                                # open a cursor to update the database
                                cursor = conn.cursor()
                                
                                # Generate a new secure hash for the new password
                                new_hash = generate_hash(recovery_pass.strip())
                                

                                ## Run an update query using parameters to change their password hash value
                                cursor.execute(
                                    "UPDATE users SET password_hash = ? WHERE username = ?", 
                                    (new_hash, clean_user)
                                )
                                conn.commit() # Commit the changes permanently to SQLite
                                
                                st.success("Password Recovery Complete.")
                        else:
                            # If either security answer is wrong, reject
                            st.error("❌ Access Refused: Mismathc")

                            

    # PHASE 2: AUTHORIZED SECURE APPLICATION PLATFORM
    else:
        #show logged in user name and role in the small green box since its a .sucess therefore it by dafault green
        st.sidebar.success(f"Agent: {st.session_state.username}\n\nAccess Role: {st.session_state.role}")
        
        # The navigation menu based on user role
        menu_options = ["System Info (Metadata)", "Cyber Incidents", "IT Service Tickets", "Cyber_AI"]
        if st.session_state.role == "Admin":
            menu_options.append("Admin Panel")  # Only admins see this-
        
        page_choice = st.sidebar.radio( #radio button selection for the menu selection 
            "Select from:", 
            menu_options
        )
        
        
        st.sidebar.markdown("---")
        if st.sidebar.button("Logout"):#logout button
            #the app restarts goes back to login page
            st.session_state.logged_in = False
            st.session_state.username = None
            st.session_state.role = None
            st.rerun()

        # Route dynamically over selected fragments 
        if page_choice == "System Info (Metadata)":
            render_metadata_lazy()
            
        elif page_choice == "Cyber Incidents":
            render_cyber_incidents_lazy()
            
        elif page_choice == "IT Service Tickets":
            render_it_tickets_lazy()
            
        elif page_choice == "Cyber_AI":
            # import pre-configured data structures (data types) 
            # that the Gemini API requires to understand your inputs.
            from google.genai import types

            st.subheader("🤖 Cyber_AI")
            st.caption("Cybersecurity Agent.")

            # get API key from Streamlit's secure secrets store
            try:
                api_key_Gemini = st.secrets["GEMINI_API_KEY"]
                client = genai.Client(api_key=api_key_Gemini) #created an object that know how to work with gemini
            except Exception:
                st.error("Security Alert: API_KEY missing")
                st.stop()

            # Setup Persistent Session Chat History Arrays
            if "ai_chat_history" not in st.session_state:
                st.session_state.ai_chat_history = [] #if history tracker does exist, build an empty list

            
            # Create a clean, collapsible container that stays closed by default
            with st.expander("Chat Session History", expanded=False):
                # If the chat history list is empty, show an information box
                if not st.session_state.ai_chat_history:
                    st.info("No queries recorded yet.")
                else:
                    
                    #NOTE:Used AI (Gemini) to get through the HISTORY related part 
                    # Loop through the temporary in-memory list to show the raw stored data
                    for i, message in enumerate(st.session_state.ai_chat_history):
                        # Identify if the message was sent by the user or generated by the AI
                        role_label = "👤 User Query" if message["role"] == "user" else "🤖 AI Response"
                        st.markdown(f"**{role_label}:** {message['content']}")
                    
                    # Draw a clean horizontal line
                    st.write("---")
                    
                    # Provide an button that lets the user clear the memory 
                    if st.button("Clear History", use_container_width=True):
                        st.session_state.ai_chat_history = [] # Wipe the list to empty
                        st.success("Session memory cleared successfully!")
                        st.rerun() # Refresh the page instantly to clear the UI
            


            # Render Historical Chat Log Items
            for message in st.session_state.ai_chat_history:
                with st.chat_message(message["role"]):
                    st.markdown(message["content"])

            #Handle Live User Prompts
            #a message text bar is created
            if user_prompt := st.chat_input("Ask a cybersecurity question..."):
                # Instantly display the user message inside the frame layout
                with st.chat_message("user"):
                    st.markdown(user_prompt)
                
                # Commit to local session history array
                st.session_state.ai_chat_history.append({"role": "user", "content": user_prompt})

               
                #prompt the ai so as it becomes contextualized according the project 
                system_instruction = (
                    "You are a strict, elite Cybersecurity Expert assistant named Cyber_AI. "
                    "Your operational boundary is strictly locked to this specific project. "
                    "You are ONLY allowed to answer questions regarding the components, datasets, "
                    "technologies, and cybersecurity concepts present in this project.\n\n"
                    
                    "APPROVED TOPICS YOU MUST ANSWER:\n"
                    "1. System Info / Metadata: Questions about 'datasets_metadata.csv' or metadata in general.\n"
                    "2. Cyber Incidents: Trends, logs, or analysis regarding 'cyber_incidents.csv'.\n"
                    "3. IT Service Tickets: Questions regarding managing and analyzing 'it_tickets.csv'.\n"
                    "4. User Security & Databases: SQLite tables (users), bcrypt hashing, salts, and password recovery.\n"
                    "5. Network Infrastructure, that may relate to the project only\n\n"
                    
                    "STRICT DECLINE RULE:\n"
                    "If the user asks about general knowledge, historical figures, politicians, sports, weather, "
                    "or ANY topic completely outside of the project's datasets, databases, or networking lab, "
                    "you must politely but firmly decline to answer by stating exactly:\n"
                    "'Access Denied: As a specialized cybersecurity system, I cannot answer questions outside this project domain.'"
                )

                # Connect to the Engine with strict system rules enforced
                with st.chat_message("assistant"):
                    with st.spinner("Processing..."):#show this message while waiting 
                        try:
                            # Convert our flat chat history format into the structure the Gemini SDK expects
                            formatted_contents = [] #empty list created 
                            for msg in st.session_state.ai_chat_history: #loop through every mes in chat history
                                formatted_contents.append( # convert each msg into goole sdk schema 
                                    types.Content(
                                        role="user" if msg["role"] == "user" else "model",#chnage assitan label to googles model one
                                        parts=[types.Part.from_text(text=msg["content"])] #wrap the text string so the api can read it safely
                                    )
                                )

                            #send chat history over the internet to gemini 
                            response = client.models.generate_content(
                                model='gemini-3.1-flash-lite',  # Running on the reliable stable baseline or gemini-3.1-flash-lite
                                #or gemini-3.5-flash-lite
                                contents=formatted_contents,
                                config=types.GenerateContentConfig(  #custom configuration
                                    system_instruction=system_instruction,
                                    temperature=0.2, # Low temperature so it stay factual and follow the given rules
                                )
                            )
                            
                            ai_output = response.text #extract the plain answer text out of google's response 
                            st.markdown(ai_output) #display ai response 
                            
                            # Commit response to history log tracking arrays
                            st.session_state.ai_chat_history.append({"role": "assistant", "content": ai_output})
                            
                        except Exception as e:
                            st.error(f"Execution Failure: {str(e)}") #handles error
        
        #this is for the admin section 
        elif page_choice == "Admin Panel":
            if st.session_state.role == "Admin":
                render_admin_panel(conn) 
            else:
                st.error(" Access Denied ❌: Admin Only.")

if __name__ == '__main__':
        main()
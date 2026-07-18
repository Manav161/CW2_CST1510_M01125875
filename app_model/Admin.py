import streamlit as st 
#for the admin section to work import from user.py
from app_model.user import get_all_users , update_user_role, delete_user, reset_lockout


# ADMIN credentials 
#plaintext for the user name
ADMIN_USERNAME = "ben"

#hashed password generated from the Admin_PWHash.py
ADMIN_HASHED_PW = b'$2b$12$Hbl1uj8f4tWDMaVbFRMKBuNk1WCX06ynNWcU7uA9e7Q1jd1YTBgp.'

def render_admin_panel(conn):
    #title 
    st.title("🛡️ Administrative Control Center")
    st.write("Manage registered platform users and system permission levels.")
    st.markdown("---")
    
    # USER TABLE
    st.subheader("👥 Platform User Directory")
    
    # Retrieve only username and role from database to df 
    users_df = get_all_users(conn)
    st.dataframe(users_df, use_container_width=True)#display table and autofit the screen 
    st.markdown("---")
    
    #ADMINISTRATIVE ACTIONS 
    st.subheader("⚙️ Administrative Actions")
    col1, col2, col3 = st.columns(3) #split layout into 3 parts side by side 
    
    # covert the username form the database df to a list for drop menus
    all_usernames = users_df['username'].tolist()
    
    # Col1: Update User Permission Role
    with col1:
        st.markdown("#### 🔄 Modify User Role")
        #choose the role from the dropdown menu
        target_user = st.selectbox("Select User Account:", all_usernames, key="change_role_user")
        assigned_role = st.selectbox("Select New Permission level:", ["User", "Admin"], key="change_role_val")
        
        #check the session state to ensure logged in-admin do not accidentally demote themsleve
        if st.button("Update Role", type="primary"):
            # Prevent the admin from accidentally removing their own admin status
            if target_user == st.session_state.get("username"):
                st.error("Access Denied: You cannot modify your own administrative role!")
            else:
                #the selected user get updated accordinly 
                update_user_role(conn, target_user, assigned_role)
                st.success(f"Successfully updated {target_user} to {assigned_role}!")
                st.rerun() # Refresh the page to show the updated role in the table
                
    # Col2: Delete User Account
    with col2:
        st.markdown("#### Delete User Account 🗑️")
        #slect account to pick from dropdown
        target_delete = st.selectbox("Select User to Delete:", all_usernames, key="delete_user_select")
        
        # Security confirmation checkbox to prevent accidental deletions
        confirm_checkbox = st.checkbox(f"Confirm that you want to delete '{target_delete}' permanently.")
        
        if st.button("Delete Account", type="secondary"):
            # Block an admin from deleting themselves
            if target_delete == st.session_state.get("username"):
                st.error("Access Denied: You cannot delete your own active account!")
            elif not confirm_checkbox:
                st.warning("Please check the confirmation box before deleting.")#warning message
            else:
                #delete the selected user
                delete_user(conn, target_delete)
                st.success(f"User '{target_delete}' has been completely removed from the system.")
                st.rerun()  # Refresh the page to remove them from the table instantly

    with col3:
        st.markdown(" 🔓 Unlock User Account ")
        # Let the admin select a user from the platform directory
        target_unlock = st.selectbox("Select Locked User:", all_usernames, key="admin_unlock_select")
        
        if st.button("Clear Lockout / Reset Tries", type="secondary"):
            # Call the database function to reset their attempts to 0 and clear timestamps
            #call the helper function to erase the login attemps and reset it
            reset_lockout(conn, target_unlock)
            st.success(f"Successfully cleared attempts and unlocked '{target_unlock}'!")
            st.rerun() # Refresh the admin panel directory

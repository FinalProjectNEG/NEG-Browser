void SavePasswordMessageDelegate::DisplaySavePasswordPrompt(
    content::WebContents* web_contents,
    std::unique_ptr<password_manager::PasswordFormManagerForUI> form_to_save) {
  DCHECK_NE(nullptr, web_contents);
  DCHECK(form_to_save);

  // Dismiss previous message if it is displayed.
  DismissSavePasswordPrompt();
  DCHECK(message_ == nullptr);

  Profile* profile =
      Profile::FromBrowserContext(web_contents->GetBrowserContext());
  // is_saving_google_account indicates whether the user is syncing
  // passwords to their Google Account.
  const bool is_saving_google_account =
      password_bubble_experiment::IsSmartLockUser(
          ProfileSyncServiceFactory::GetForProfile(profile));

  base::Optional<AccountInfo> account_info =
      password_manager::GetAccountInfoForPasswordMessages(
          profile, is_saving_google_account);
  // All the DisplaySavePasswordPrompt parameters are passed to CreateMessage to
  // avoid a call to MessageDispatcherBridge::EnqueueMessage from test while
  // still providing decent test coverage.
  CreateMessage(web_contents, std::move(form_to_save), account_info);

  messages::MessageDispatcherBridge::EnqueueMessage(message_.get(),
                                                    web_contents_);
}

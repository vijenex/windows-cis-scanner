# 1 Account Policies (Windows Server 2025) — Audit-only
$Global:Rules += @(
  # 1.1 Password Policy
  @{ 
    Id='1.1.1'
    Title='(L1) Ensure ''Enforce password history'' is set to ''24 or more password(s)'' (Automated)'
    Section='1.1 Password Policy'
    Profile='Level1'
    Type='SecEdit'
    SectionName='System Access'
    Key='PasswordHistorySize'
    Operator='GreaterOrEqual'
    Expected=24
    Description='This policy setting determines the number of renewed, unique passwords that have to be associated with a user account before you can reuse an old password. The value for this policy setting must be between 0 and 24 passwords. The default value for stand-alone systems is 0 passwords, but the default setting when joined to a domain is 24 passwords. To maintain the effectiveness of this policy setting, use the Minimum password age setting to prevent users from repeatedly changing their password. The recommended state for this setting is: 24 or more password(s).'
    Impact='The major impact of this configuration is that users must create a new password every time they are required to change their old one. If users are required to change their passwords to new unique values, there is an increased risk of users who write their passwords somewhere so that they do not forget them. Another risk is that users may create passwords that change incrementally (for example, password01, password02, and so on) to facilitate memorization but make them easier to guess.'
    Remediation='To establish the recommended configuration via GP, set the following UI path to 24 or more password(s): Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Password Policy\Enforce password history'
  },
  @{ 
    Id='1.1.2'
    Title='(L1) Maximum password age: 365 or fewer days, but not 0'
    Section='1.1 Password Policy'
    Profile='Level1'
    Type='Composite'
    AllOf=@(
        @{ SectionName='System Access'; Key='MaximumPasswordAge'; Operator='LessOrEqual'; Expected=365 },
        @{ SectionName='System Access'; Key='MaximumPasswordAge'; Operator='NotEquals'; Expected=0 }
    )
    Description='This policy setting defines how long a user can use their password before it expires.Values for this policy setting range from 0 to 999 days. If you set the value to 0, the password will never expire. Because attackers can crack passwords, the more frequently you change the password the less opportunity an attacker has to use a cracked password. However, the lower this value is set, the higher the potential for an increase in calls to help desk support due to users having to change their password or forgetting which password is current. The recommended state for this setting is 365 or fewer days, but not 0.'
    Impact='If the Maximum password age setting is too low, users are required to change their passwords very often. Such a configuration can reduce security in the organization, because users might write their passwords in an insecure location or lose them. If the value for this policy setting is too high, the level of security within an organization is reduced because it allows potential attackers more time in which to discover user passwords or to use compromised accounts.'
    Remediation='To establish the recommended configuration via GP, set the following UI path to 365 or fewer days, but not 0: Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Password Policy\Maximum password age Default Value: 42 days.'
  },
  @{ 
    Id='1.1.3'
    Title='(L1) Minimum password age: 1 or more day(s)'
    Section='1.1 Password Policy'
    Profile='Level1'
    Type='SecEdit'
    SectionName='System Access'
    Key='MinimumPasswordAge'
    Operator='GreaterOrEqual'
    Expected=1
    Description='This policy setting determines the number of days that you must use a password before you can change it. The range of values for this policy setting is between 1 and 999 days. (You can also set the value to 0 to allow immediate password changes.) The default value for this setting is 0 days.'
    Impact='Users might be inclined to cycle back to a password they have used before. The Minimum password age policy setting is used with the Enforce password history policy setting to prevent this. For example, if the Enforce password history setting is configured to ensure that users cannot reuse any of their last 12 passwords, they could change their password 13 times in a few minutes and reuse the password they started with, unless you also configure the Minimum password age policy setting to a number that is greater than 0.'
    Remediation='To establish the recommended configuration via GP, set the following UI path to 1 or more day(s): Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Password Policy\Minimum password age'
  },
  @{ 
    Id='1.1.4'
    Title='(L1) Minimum password length: 14 or more'
    Section='1.1 Password Policy'
    Profile='Level1'
    Type='SecEdit'
    SectionName='System Access'
    Key='MinimumPasswordLength'
    Operator='GreaterOrEqual'
    Expected=14
    Description='This policy setting determines the least number of characters that make up a password for a user account. There are many different theories about how to determine the best password length for an organization, but perhaps "pass phrase" is a better term than "password." In Microsoft Windows 2000 or later, pass phrases can be quite long and can include spaces. Therefore, a phrase such as "I want to drink a $5 milkshake" is a valid pass phrase. It is considerably longer than most passwords, easy to remember, includes a mix of upper- and lowercase letters, and includes a number and a special character. A pass phrase such as this would be much more difficult to attack than an 8-character password that includes a mix of upper- and lowercase letters, numbers, and special characters.'
    Impact='The impact of this configuration should be minimal because all users should be able to comply with the requirement easily.'
    Remediation='To establish the recommended configuration via GP, set the following UI path to 14 or more character(s): Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Password Policy\Minimum password length'
  },
  @{ 
    Id='1.1.5'
    Title='(L1) Password must meet complexity requirements: Enabled'
    Section='1.1 Password Policy'
    Profile='Level1'
    Type='SecEdit'
    SectionName='System Access'
    Key='PasswordComplexity'
    Operator='Equals'
    Expected=1
    Description='This policy setting checks all new passwords to ensure that they meet basic requirements for strong passwords. When this policy is enabled, passwords must meet the following minimum requirements: Not contain the user''s account name or parts of the user''s full name that exceed two consecutive characters; Be at least six characters in length; Contain characters from three of the following four categories: English uppercase characters (A through Z); English lowercase characters (a through z); Base 10 digits (0 through 9); Non-alphabetic characters (for example, !, $, #, %).'
    Impact='If the default password complexity policy is implemented, additional help desk calls for locked-out accounts could occur because users might not be accustomed to passwords that contain non-alphabetic characters, or they might have problems entering passwords that contain accented characters or symbols on keyboards with different layouts.'
    Remediation='To establish the recommended configuration via GP, set the following UI path to Enabled: Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Password Policy\Password must meet complexity requirements'
  },
  @{ 
    Id='1.1.6'
    Title='(L1) Relax minimum password length limits: Enabled'
    Section='1.1 Password Policy'
    Profile='Level1'
    Type='SecEdit'
    SectionName='System Access'
    Key='RelaxMinimumPasswordLengthLimits'
    Operator='Equals'
    Expected=1
    Description='This policy setting determines whether the minimum password length setting can be increased beyond the 14-character limit that was enforced in earlier versions of Windows. Enabling this policy setting allows minimum password lengths of up to 128 characters.'
    Impact='None. This is the default configuration.'
    Remediation='To establish the recommended configuration via GP, set the following UI path to Enabled: Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Password Policy\Relax minimum password length limits'
  },
  @{ 
    Id='1.1.7'
    Title='(L1) Store passwords using reversible encryption: Disabled'
    Section='1.1 Password Policy'
    Profile='Level1'
    Type='SecEdit'
    SectionName='System Access'
    Key='ClearTextPassword'
    Operator='Equals'
    Expected=0
    Description='This policy setting determines whether the operating system stores passwords in a way that uses reversible encryption, which provides support for application protocols that require knowledge of the user''s password for authentication purposes. Passwords that are stored with reversible encryption are essentially the same as plaintext versions of the passwords.'
    Impact='None. This is the default configuration.'
    Remediation='To establish the recommended configuration via GP, set the following UI path to Disabled: Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Password Policy\Store passwords using reversible encryption'
  },

  # 1.2 Account Lockout Policy
  @{ 
    Id='1.2.1'
    Title='(L1) Account lockout duration: 15 or more minutes'
    Section='1.2 Account Lockout Policy'
    Profile='Level1'
    Type='SecEdit'
    SectionName='System Access'
    Key='LockoutDuration'
    Operator='GreaterOrEqual'
    Expected=15
    Description='This policy setting determines the length of time that must pass before a locked account is unlocked and a user can try to log on again. The setting does this by specifying the number of minutes a locked account will remain unavailable. If the value for this policy setting is configured to 0, locked accounts will remain locked until an administrator unlocks them manually.'
    Impact='If you configure the Account lockout duration policy setting to 0, a locked account will remain locked until an administrator unlocks it manually. If you configure this policy setting to a non-zero value, users might have to wait the specified amount of time before they can log on to their computers again after their accounts are locked. This delay might result in a large number of help desk calls.'
    Remediation='To establish the recommended configuration via GP, set the following UI path to 15 or more minute(s): Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Account Lockout Policy\Account lockout duration'
  },
  @{ 
    Id='1.2.2'
    Title='(L1) Account lockout threshold: 5 or fewer, not 0'
    Section='1.2 Account Lockout Policy'
    Profile='Level1'
    Type='Composite'
    AllOf=@(
        @{ SectionName='System Access'; Key='LockoutBadCount'; Operator='LessOrEqual'; Expected=5 },
        @{ SectionName='System Access'; Key='LockoutBadCount'; Operator='NotEquals'; Expected=0 }
    )
    Description='This policy setting determines the number of failed logon attempts before the account is locked. You can set the value between 1 and 999 failed logon attempts, or you can specify that the account will never be locked by setting the value to 0. If Account lockout threshold is defined, the Account lockout duration must be greater than or equal to the value for Reset account lockout counter after.'
    Impact='If this policy setting is enabled, a locked account cannot be used until you reset it manually or until the lockout duration expires. If you set the lockout threshold too low, users could be locked out frequently and productivity could be affected. If the threshold is set too high, there is less security against brute force password attacks.'
    Remediation='To establish the recommended configuration via GP, set the following UI path to 5 or fewer invalid logon attempt(s), but not 0: Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Account Lockout Policy\Account lockout threshold'
  },
  @{ 
    Id='1.2.3'
    Title='(L1) Allow Administrator account lockout: Enabled (MS only)'
    Section='1.2 Account Lockout Policy'
    Profile='Level1'
    Type='Manual'
    Expected='Enabled'
    Evidence='Local Security Policy path noted in report'
    Description='This policy setting determines whether the local Administrator account is subject to account lockout policy. This setting only applies to the local Administrator account, not to other accounts that are members of the Administrators group.'
    Impact='If you enable this policy setting, the local Administrator account will be subject to account lockout policy like any other account. If you disable this policy setting, the local Administrator account cannot be locked out, regardless of the Account lockout threshold policy setting.'
    Remediation='To establish the recommended configuration via GP, set the following UI path to Enabled: Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Account Lockout Policy\Allow Administrator account lockout'
  },
  @{ 
    Id='1.2.4'
    Title='(L1) Reset account lockout counter after: 15+ minutes'
    Section='1.2 Account Lockout Policy'
    Profile='Level1'
    Type='SecEdit'
    SectionName='System Access'
    Key='ResetLockoutCount'
    Operator='GreaterOrEqual'
    Expected=15
    Description='This policy setting determines the length of time before the Account lockout threshold resets to zero. The default value for this policy setting is Not Defined. If Account lockout threshold is defined, this reset time must be less than or equal to the value for Account lockout duration.'
    Impact='Users could be locked out of their accounts if they mistype their password multiple times. To reduce the chance of such accidental lockouts, the Reset account lockout counter after setting determines the time that must elapse before the counter that tracks failed logon attempts and triggers lockouts is reset to 0.'
    Remediation='To establish the recommended configuration via GP, set the following UI path to 15 or more minute(s): Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Account Lockout Policy\Reset account lockout counter after'
  }
)
# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104660");
  script_version("2023-03-31T10:08:38+0000");
  script_tag(name:"last_modification", value:"2023-03-31 10:08:38 +0000 (Fri, 31 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-29 12:40:32 +0000 (Wed, 29 Mar 2023)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Revoked 'known_hosts' SSH Key Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"The remote host is using (a) revoked SSH key(s) in (a)
  'known_hosts' file(s).");

  script_tag(name:"vuldetect", value:"Logs in via SSH and checks all found 'known_hosts' related
  files for revoked SSH key(s).");

  script_tag(name:"impact", value:"An attacker could use this situation to compromise or eavesdrop
  on the SSH communication between the client and the server using a man-in-the-middle attack.");

  script_tag(name:"solution", value:"Remove the revoked SSH key(s) from the reported 'known_hosts'
  file(s).");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("ssh_func.inc");

if( ! sock = ssh_login_or_reuse_connection() )
  exit( 0 );

# e.g.:
# ~/.ssh/known_hosts
# /etc/ssh/ssh_known
# /etc/ssh/ssh_known_hosts
# nb: Using the regex below like this is expected to make it easier to read
if( ! full_path_list = ssh_find_file( file_name:"/(ssh_known_hosts|ssh_known|known_hosts)$", sock:sock, useregex:TRUE ) ) {
  ssh_close_connection();
  exit( 0 );
}

revoked_ssh_keys = make_array(
  # From https://web.archive.org/web/20230320230907/https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints
  "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==",
  "GitHub.com (https://github.blog/2023-03-23-we-updated-our-rsa-ssh-host-key/)"
);

report = "The following revoked SSH key(s) have been identified:";
found = FALSE;

foreach full_path( full_path_list ) {

  if( ! full_path = chomp( full_path ) )
    continue;

  res = ssh_cmd( socket:sock, cmd:"cat " + full_path, return_errors:FALSE );

  # nb: Just a basic response verification to avoid an unnecessary foreach loop below if the
  # response isn't containing the expected info.
  if( ! res || res !~ "[a-z0-9-]+ [a-zA-Z0-9]+" )
    continue;

  foreach revoked_ssh_key( keys( revoked_ssh_keys ) ) {
    if( revoked_ssh_key >< res ) {
      report += '\n';
      report += '\nSSH key:       ' + revoked_ssh_key;
      report += '\nFile location: ' + full_path;
      report += '\nReference:     ' + revoked_ssh_keys[revoked_ssh_key];
      found = TRUE;
    }
  }
}

ssh_close_connection();

if( found ) {
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

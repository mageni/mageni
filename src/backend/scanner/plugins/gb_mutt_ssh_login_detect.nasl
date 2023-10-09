# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900675");
  script_version("2023-09-14T05:05:34+0000");
  script_tag(name:"last_modification", value:"2023-09-14 05:05:34 +0000 (Thu, 14 Sep 2023)");
  script_tag(name:"creation_date", value:"2009-06-24 07:17:25 +0200 (Wed, 24 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"executable_version");

  script_name("Mutt Detection (Linux/Unix SSH Login)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of Mutt.");

  script_xref(name:"URL", value:"http://www.mutt.org/");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

paths = ssh_find_bin(prog_name:"mutt", sock:sock);

foreach executableFile (paths) {

  executableFile = chomp(executableFile);
  if(!executableFile)
    continue;

  muttVer = ssh_get_bin_version(full_prog_name:executableFile, sock:sock, version_argv:"-v", ver_pattern:"Mutt (([0-9.]+)([a-z])?)");
  if(!isnull(muttVer[1])) {

    set_kb_item(name:"mutt/detected", value:TRUE);

    # nb: Don't use muttVer[max_index(muttVer)-1]) for the concluded string because the output is quite huge (around 60 lines)...
    register_and_report_cpe( app:"Mutt", ver:muttVer[1], concluded:muttVer[0], base:"cpe:/a:mutt:mutt:", expr:"^([0-9.]+)", insloc:executableFile, regPort:0, regService:"ssh-login" );
  }
}

ssh_close_connection();
exit(0);

# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150499");
  script_version("2020-12-16T14:37:19+0000");
  script_tag(name:"last_modification", value:"2020-12-16 14:37:19 +0000 (Wed, 16 Dec 2020)");
  script_tag(name:"creation_date", value:"2020-11-26 14:08:34 +0000 (Thu, 26 Nov 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Get crontab and /etc/cron.* scripts");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gather-package-list.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"https://linux.die.net/man/1/crontab");
  script_xref(name:"URL", value:"https://linuxconfig.org/linux-crontab-reference-guide");

  script_tag(name:"summary", value:"Crontab is the program used to install, remove or list the
tables used to drive the cron(8) daemon. Each user can have their own crontab, and though these are
files in /var/spool/, they are not intended to be edited directly. For SELinux in mls mode can be
even more crontabs - for each range.

Many of the services use crontab automatically. They store their crontab scheduler configuration
directly into /etc/cron.d directory. Any files located in this directory are automatically picked
up and executed by the crontab scheduler.

Linux system administrators can also take an advantage of crontab preconfigured schedules
directories /etc/cron.daily, /etc/cron.hourly, /etc/cron.monthly and /etc/cron.weekly.

The crontab files located within these directories are periodically traversed and execute by crontab
scheduler. So for example crontab files found in /etc/cron.daily directory are executed every day.
Furthermore, if root wishes to run eg. backup.sh script once a week he will place it into
/etc/cron.weekly directory.

Note: This script gets the crontab for root user and content of files /etc/cron.*");

  exit(0);
}

include( "ssh_func.inc" );
include( "policy_functions.inc" );

if( ! get_kb_item( "login/SSH/success" ) || ! sock = ssh_login_or_reuse_connection() ) {
  set_kb_item( name:"Policy/linux/crontab/ssh/error", value:TRUE );
  exit( 0 );
}

cmd = "crontab -u root -l";
crontab = ssh_cmd( socket:sock, cmd:cmd, return_errors:FALSE );

if( crontab ) {
  set_kb_item( name:"Policy/linux/cronfilelist", value:"root_crontab" );
  set_kb_item( name:"Policy/linux/cronfilelist/root_crontab/content", value:crontab );
}

cmd = "find /etc/cron* -type f";
cron_file_list = ssh_cmd( socket:sock, cmd:cmd, return_errors:FALSE );
if( ! cron_file_list ) {
  set_kb_item( name:"Policy/linux/cronfilelist/error", value:TRUE );
} else {
  foreach file( split( cron_file_list, keep:FALSE ) ) {
    set_kb_item( name:"Policy/linux/cronfilelist", value:file );
    policy_linux_file_content( socket:sock, file:file );
  }
}

exit( 0 );
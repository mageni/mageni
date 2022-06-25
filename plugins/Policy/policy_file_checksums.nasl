###############################################################################
# OpenVAS Vulnerability Test
# $Id: policy_file_checksums.nasl 10678 2018-07-30 09:29:11Z cfischer $
#
# Check File Checksums
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
# Thomas Rotter <thomas.rotter@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103940");
  script_version("$Revision: 10678 $");
  script_name("File Checksums");
  script_tag(name:"last_modification", value:"$Date: 2018-07-30 11:29:11 +0200 (Mon, 30 Jul 2018) $");
  script_tag(name:"creation_date", value:"2013-08-14 16:47:16 +0200 (Wed, 14 Aug 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_category(ACT_GATHER_INFO);
  script_family("Policy");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"https://documentation.mageni.net");

  script_add_preference(name:"Target checksum File", type:"file", value:"");
  script_add_preference(name:"List all and not only the first 100 entries", type:"checkbox", value:"no");

  script_tag(name:"summary", value:"Checks the checksums (MD5 or SHA1)of specified files.

  The SSH protocol is used to log in and to gather the needed information");

  script_tag(name:"qod", value:"98"); # direct authenticated file analysis is pretty reliable

  script_timeout(600);

  exit(0);
}

checksumlist = script_get_preference( "Target checksum File" );
if( ! checksumlist ) exit( 0 );

checksumlist = script_get_preference_file_content( "Target checksum File" );
if( ! checksumlist ) exit( 0 );

include("ssh_func.inc");

function exit_cleanly() {
  set_kb_item( name:"policy/file_checksums/no_timeout", value:TRUE );
  exit(0);
}

function check_md5( md5 ) {
  local_var md5;
  if( ereg( pattern:"^[a-f0-9]{32}$", string:md5 ) )
    return TRUE;
  else
    return FALSE;
}

function check_sha1( sha1 ) {
  local_var sha1;
  if( ereg( pattern:"^[a-f0-9]{40}$", string:sha1 ) )
    return TRUE;
  else
    return FALSE;
}

function check_ip( ip ) {
  local_var ip;
  if( ereg( pattern:"([0-9]{1,3}\.){3}[0-9]{1,3}$", string:ip ) )
    return TRUE;
  else
    return FALSE;
}

function check_file( file ) {
  local_var file, unallowed, ua;
  unallowed = make_list("#",">","<",";",'\0',"!","'",'"',"$","%","&","(",")","?","`","*"," |","}","{","[","]");
  foreach ua( unallowed ) {
    if( ua >< file ) return FALSE;
  }
  if( ! ereg( pattern:"^/.*$", string:file ) )
    return FALSE;
  else
    return TRUE;
}

listall = script_get_preference("List all and not only the first 100 entries");
maxlist = 100;
host_ip = get_host_ip();
valid_lines_list = make_list();

set_kb_item(name:"policy/file_checksums/started", value:TRUE);

lines = split(checksumlist, keep:FALSE);
line_count = max_index(lines);

if (line_count == 1 && lines[0] =~ "Checksum\|File\|Checksumtype(\|Only-Check-This-IP)?") {
  set_kb_item(name:"policy/file_checksums/general_error_list", value:"Attached checksum File doesn't contain test entries (Only the header is present).");
  exit_cleanly();
}

x = 0;
foreach line (lines) {
  x++;
  if (!eregmatch(pattern:"((Checksum\|File\|Checksumtype(\|Only-Check-This-IP)?)|([a-f0-9]{32,40}\|.*\|(sha1|md5)))", string:line)) {
    if (x == line_count && eregmatch(pattern:"^$", string:line))
      continue;  # accept one empty line at the end of checksumlist.
    set_kb_item(name:"policy/file_checksums/invalid_list", value:line + "|invalid line error|error;");
    continue;
  }
  # Ignore the header of the checksum file
  if (!eregmatch(pattern:"(Checksum\|File\|Checksumtype(\|Only-Check-This-IP)?)", string:line))
    valid_lines_list = make_list( valid_lines_list, line );
}

port = kb_ssh_transport();

sock = ssh_login_or_reuse_connection();
if (!sock) {
  error = get_ssh_error();
  if (!error)
    error = "No SSH Port or Connection!";
  set_kb_item(name:"policy/file_checksums/general_error_list", value:error);
  exit_cleanly();
}

if (listall == "yes"){
  max = max_index(valid_lines_list);
} else {
  maxindex = max_index(valid_lines_list);
  if (maxindex < maxlist)
    max = maxindex;
  else
    max = maxlist;
}

for (i=0; i<max; i++) {
  val = split(valid_lines_list[i], sep:'|', keep:FALSE);
  checksum   = tolower(val[0]);
  filename   = val[1];
  algorithm  = tolower(val[2]);

  if (max_index(val) == 4) {
    ip = val[3];
    if (!check_ip(ip:ip)) {
      set_kb_item(name:"policy/file_checksums/invalid_list", value:valid_lines_list[i] + '|ip format error|error;');
      continue;
    }
    if (ip && ip != host_ip)
      continue;
  }

  if (!checksum || !filename || !algorithm) {
    set_kb_item(name:"policy/file_checksums/invalid_list", value:valid_lines_list[i] + '|error reading line|error;');
    continue;
  }

  if (!check_file(file:filename)) {
    set_kb_item(name:"policy/file_checksums/invalid_list", value:valid_lines_list[i] + '|filename format error|error;');
    continue;
  }

  if (algorithm == "md5") {
    if (!check_md5(md5:checksum)) {
      set_kb_item(name:"policy/file_checksums/invalid_list", value:valid_lines_list[i] + '|md5 format error|error;');
      continue;
    }

    sshval = ssh_cmd(socket:sock, cmd:"LC_ALL=C md5sum " + " '" + filename + "'");
    if (sshval !~ ".*No such file or directory") {
      md5val = split(sshval, sep:' ', keep:FALSE);
      if (tolower(md5val[0]) == checksum) {
        set_kb_item(name:"policy/file_checksums/md5_ok_list", value:filename + '|' + md5val[0] + '|pass;');
      } else {
        set_kb_item(name:"policy/file_checksums/md5_violation_list", value:filename + '|' + md5val[0] + '|fail;');
      }
    } else {
      set_kb_item(name:"policy/file_checksums/md5_error_list", value:filename + '|No such file or directory|error;');
    }
  } else {
    if (algorithm == "sha1") {
      if (!check_sha1(sha1:checksum)) {
        set_kb_item(name:"policy/file_checksums/general_error_list", value:valid_lines_list[i] + '|sha1 format error|error;');
        continue;
      }

      sshval = ssh_cmd(socket:sock, cmd:"LC_ALL=C sha1sum " + " '" + filename + "'");
      if (sshval !~ ".*No such file or directory") {
        sha1val = split(sshval, sep:' ', keep:FALSE);
          if (tolower(sha1val[0]) == checksum) {
            set_kb_item(name:"policy/file_checksums/sha1_ok_list", value:filename + '|' + sha1val[0] + '|pass;');
          } else {
            set_kb_item(name:"policy/file_checksums/sha1_violation_list", value:filename + '|' + sha1val[0] + '|fail;');
          }
      } else {
        set_kb_item(name:"policy/file_checksums/sha1_error_list", value:filename + '|No such file or directory|error;');
      }
    }
  }
}

exit_cleanly();

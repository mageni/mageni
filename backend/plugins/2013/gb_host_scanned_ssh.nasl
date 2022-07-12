###############################################################################
# OpenVAS Vulnerability Test
#
# Leave information on scanned hosts
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103625");
  script_version("2019-04-18T08:49:33+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-04-18 08:49:33 +0000 (Thu, 18 Apr 2019)");
  script_tag(name:"creation_date", value:"2012-12-14 10:37:58 +0100 (Fri, 14 Dec 2012)");
  script_name("Leave information on scanned hosts");
  script_category(ACT_END);
  script_family("General");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("host_scan_end.nasl", "gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");

  script_add_preference(name:"Enable", type:"checkbox", value:"no");

  script_add_preference(name:"Use File", type:"checkbox", value:"no");
  script_add_preference(name:"File name /tmp/", type:"entry", value:"scan_info.txt");
  script_add_preference(name:"Append to File", type:"checkbox", value:"no");

  script_add_preference(name:"Use Syslog", type:"checkbox", value:"no");
  script_add_preference(name:"Syslog priority", type:"radio", value:"info;debug;notice;warning;err;crit;alert;emerg");
  script_add_preference(name:"Syslog tag", type:"entry", value:"VulScan");

  script_add_preference(name:"Message", type:"entry", value:"Security Scan of ::HOSTNAME:: finished. Start: ::SCAN_START:: Stop: ::SCAN_STOP::");

  script_tag(name:"summary", value:"This routine stores information about the scan on the scanned host,
  provided it is a unixoid system offering ssh access with a standard shell.

  The information cover hostname, scan start time and scan end time.
  No details about the actual scan results are stored on the scanned host.

  By default, this routine is disabled even it is selected to run. To activate
  it, it needs to be explicitly enabled with its corresponding preference switch.

  The preference 'Message' may contain 3 placeholder where respective content
  will be inserted into the message when the message is finally created on the
  target system:

  '::HOSTNAME::', '::SCAN_START::' and '::SCAN_STOP::'.

  Two methods are offered (one or even both concurrently can be used):

  * Syslog: The utility 'logger' on the target system is used to issue the
  message. The message will appear in the standard log environment as configured
  on the corresponding target system. Error is reported in case the logger
  utility is not available.

  * File: A filename under /tmp can be chosen where the message is left. It is
  configurable to either overwrite the file each time or to append new
  information. A token is added to this file to ensure only files created by
  this routine are used. Error is reported when the access rights are not
  sufficient or symbolic links detected.");

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("ssh_func.inc");

enabled = script_get_preference("Enable");
if("yes" >!< enabled)
  exit(0);

if(get_kb_item("ssh/no_linux_shell")){
  log_message(port:0, data:"Target system does not offer a standard shell. Can not continue.");
  exit(0);
}

soc = ssh_login_or_reuse_connection();
if(!soc)
  exit(0);

file_security_token = "b3BlbnZhcy1zY2FubmVyLXRydXN0Cg";

function get_disallowed_signs() {
  return make_list('\0',"'");
}

function get_disallowed_str() { # display disallowed signs in log_message()

  disallowed = get_disallowed_signs();

  ua_str = '';
  foreach ua (disallowed) {
    ua_str += ua + ' ';
  }

  return ua_str;
}

function check_file(file) { # check given file for disallowed sign

  disallowed = get_disallowed_signs();
  disallowed = make_list("..", "/", disallowed);

  foreach ua (disallowed) {
    if(ua >< file) return FALSE;
  }
  return TRUE;
}

function check_message(message) {

  disallowed = get_disallowed_signs();

  foreach ua (disallowed) {
    if(ua >< message) return FALSE;
  }
  return TRUE;
}

function fancy_date() {
  local_var datestr;

  datestr =  _FCT_ANON_ARGS[0];
  if (int (datestr ) < 10)
    return string ("0", datestr);

  return datestr;
}

function make_date_str(date) {

  time = localtime(date);

  month  = fancy_date ( time["mon"]  );
  day    = fancy_date ( time["mday"] );
  hour   = fancy_date ( time["hour"] );
  minute = fancy_date ( time["min"]  );
  sec    = fancy_date ( time["sec"]  );

  return time["year"] +'-' + month + '-' + day + ' ' + hour + ':' + minute + ':' + sec;
}

function replace_placeholders(message) {

  local_var message;

  if("::HOSTNAME::" >< message)
    message = str_replace(string:message, find:"::HOSTNAME::",replace:get_host_name());

  if("::SCAN_START::" >< message) {

    start = get_kb_item("/tmp/start_time");

    if(start) {
      scan_start = make_date_str(date:start);
    } else {
      scan_start = 'Scan start unknown (ping_host.nasl not launched?)';
    }

    message = str_replace(string:message, find:"::SCAN_START::",replace:scan_start);
  }

  if("::SCAN_STOP::" >< message) {

    stop = get_kb_item("/tmp/stop_time");

    if(stop) {
      scan_stop = make_date_str(date:stop);
    } else { # if there is no stop time in kb, create it.
      scan_stop = make_date_str(date:unixtime());
    }

    message = str_replace(string:message, find:"::SCAN_STOP::",replace:scan_stop);
  }
  return message;
}


message = script_get_preference("Message");

if(strlen(message) < 1) {

  # Empty files are not possible. To simply create a file, the user needs to
  # apply a dummy character like a white space.
  log_message(port:0, data:"No Message was given. Can not execute this test without a message.");
  ssh_close_connection();
  exit(1);
}

if(!check_message(message:message)) {
  # we give the message to logger. So keep it clean.
  log_message(port:0, data:"Forbidden sign in 'message'. The following signs are not allowed: " + get_disallowed_str());
  ssh_close_connection();
  exit(1);
}

message = replace_placeholders(message:message);

## syslog

syslog = script_get_preference("Use Syslog");

if("yes" >< syslog) {

  syslog_tag = script_get_preference("Syslog tag");
  syslog_priority = script_get_preference("Syslog priority");

  if(syslog_tag) {
    if(!check_message(message:syslog_tag)) {
      log_message(port:0, data:"Forbidden sign in Syslog tag '" + syslog_tag
        + "'. The following signs are not allowed: " + get_disallowed_str());
      ssh_close_connection();
      exit(1);
    }
  }

  # logger installed? Should be by default on most (all?) systems.
  check4logger = ssh_cmd(socket:soc, cmd:"logger --help");

  if("not found" >< check4logger) {
    log_message(port:0, data:
      "You have enabled syslog but It seems that the 'logger' command is not" + '\n' +
      "available on the remote host." + '\n' +
      "The 'logger' utility is part of the bsdutils package on Debian-based" + '\n' +
      "systems and the util-linux-ng package on Fedora.");
    ssh_close_connection();
    exit(1);
  }

  cmd = "logger ";

  if(syslog_tag) {
    cmd += "-t '" + syslog_tag  + "' ";
  }

  if(syslog_priority) {
    cmd += "-p '" + syslog_priority  + "' ";
  }

  cmd += "-- '" + message  + "'; echo $?";

  send_message = ssh_cmd(socket:soc,cmd:cmd);
  send_message_int = int(send_message);

  if(send_message_int > 0) {
    log_message(port:0, data:"Sending message to syslog failed. Error: " + chomp(send_message));
  } else {
    log_message(port:0, data:"Message '" + message + "' successfully send to syslog.");
  }
} ## end syslog


## use a file

filelog = script_get_preference("Use File");

if("yes" >< filelog) {
  path = script_get_preference("File name /tmp/");
  append = script_get_preference("Append to File");

  path = chomp(path);

  if(!check_file(file:path)) {
    log_message(port:0, data:"Forbidden sign in filename '" + path  +
      "'. The following signs are not allowed: " + get_disallowed_str() +
      ' .. /');
    ssh_close_connection();
    exit(1);
  }

  dir_exist = ssh_cmd(socket:soc, cmd:"ls -d '/tmp'");

  if("no such file" >< tolower(dir_exist)) {
    log_message(port:0, data: "It seems that /tmp does not exist. Can't create file /tmp/" + path);
    ssh_close_connection();
    exit(1);
  }

  path = '/tmp/' + path;

  file_exist = ssh_cmd(socket:soc, cmd:"ls -l '" + path + "'");

  if(file_exist =~ "^l[^s]") { # don't work on existing symlinks.
     log_message(port:0, data:"File '" + path  +  "' is a symbolic link and this is not allowed. Can not continue.");
     ssh_close_connection();
     exit(1);
   }

  if("no such file" >!< tolower(file_exist)) { # if the file already exist...

    current_content = ssh_cmd(socket:soc, cmd:"cat '" + path + "'"); # look what is in it...

    if(strlen(current_content) > 0 ) {

      if(file_security_token >!< current_content) {
        # no security_token or not created by this nvt
        log_message(port:0, data:"Security Token '" +
          file_security_token  + "' not found in existing file '" +
          path + "'. Can not continue.");
        ssh_close_connection();
        exit(1);
      }

      if("yes" >< append) { # if we append...
        file_security_token = NULL; # ...we don't need the token because token is already present in file
      }
    }
  }

  redirect = '>';
  if("yes" >< append) {
    redirect += '>';
  }

  cmd = "echo '";

  if(file_security_token) {
    cmd += '<token>' + file_security_token + '</token>\n';
  }

  cmd += message + "' " + redirect + " '" + path + "'";
  cmd += ' ; echo $?';

  ssh_cmd(socket:soc, cmd:cmd);

  new_content = ssh_cmd(socket:soc, cmd:"cat '" + path + "'");
  if(message >!< new_content) {
    log_message(port:0, data:"Sending message to '" + path + "' failed.");
    ssh_close_connection();
    exit(1);
  } else {
    log_message(port:0, data:"Message '" + message +
      "' successfully send to '" + path  + "'.");
    ssh_close_connection();
    exit(0);
  }

} ## end use a file

ssh_close_connection();

exit(0);
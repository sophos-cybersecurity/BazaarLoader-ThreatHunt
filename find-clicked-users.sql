WITH full_list AS (
    SELECT
        linux_processes.meta_hostname AS ep_name,
        linux_processes.time AS date_time,
        NULL AS parent_process_name,
        linux_processes.name AS process_name,
        (
            SELECT DISTINCT linux_users.username
            FROM
                xdr_data AS linux_users
            WHERE
                query_name = 'user_accounts'
                AND linux_users.meta_hostname = linux_processes.meta_hostname
                AND linux_users.uid = linux_processes.uid
        ) AS user_name,
        linux_processes.cmdline AS cmd_line,
        linux_processes.pids || ':' || CAST(linux_processes.time AS VARCHAR) AS sophos_pid,
        NULL AS parent_sophos_pid,
        linux_processes.sha256 AS sha256,
        linux_processes.sha1 AS sha1,
        linux_processes.path AS path,
        NULL AS ml_score,
        NULL AS pua_score,
        NULL AS global_rep,
        NULL AS local_rep,
        linux_processes.gid AS gid,
        linux_processes.uid AS uid,
        linux_processes.euid AS euid,
        linux_processes.egid AS egid,
        NULL AS parent_path
    FROM
        xdr_data AS linux_processes
    WHERE
        linux_processes.query_name = 'running_processes_linux_events'
        AND LOWER(linux_processes.cmdline) LIKE LOWER('%googleapis.com%')

    UNION ALL

    SELECT
        windows_processes.meta_hostname AS ep_name,
        windows_processes.time AS date_time,
        windows_processes.parent_name AS parent_process_name,
        windows_processes.name AS process_name,
        windows_processes.username AS user_name,
        windows_processes.cmdline AS cmd_line,
        windows_processes.sophos_pid AS sophos_pid,
        windows_processes.parent_sophos_pid AS parent_sophos_pid,
        windows_processes.sha256 AS sha256,
        NULL AS sha1,
        windows_processes.path AS path,
        windows_processes.ml_score AS ml_score,
        windows_processes.pua_score AS pua_score,
        windows_processes.global_rep AS global_rep,
        windows_processes.local_rep AS local_rep,
        NULL AS gid,
        NULL AS uid,
        NULL AS euid,
        NULL AS egid,
        windows_processes.parent_path AS parent_path
    FROM
        xdr_data AS windows_processes
    WHERE
        windows_processes.query_name = 'running_processes_windows_sophos'
        AND LOWER(windows_processes.cmdline) LIKE LOWER('%googleapis.com%')
)

SELECT
    ARRAY_JOIN(ARRAY_AGG(DISTINCT ep_name), CHR(10)) AS ep_list,
    COUNT(DISTINCT ep_name) AS ep_count,
    process_name,
    path,
    cmd_line,
    DATE_FORMAT(FROM_UNIXTIME(MIN(date_time)), '%Y-%m-%dT%H:%i:%SZ') AS first_seen,
    DATE_FORMAT(FROM_UNIXTIME(MAX(date_time)), '%Y-%m-%dT%H:%i:%SZ') AS last_seen,
    user_name,
    parent_process_name,
    parent_path,
    ARRAY_JOIN(ARRAY_AGG(DISTINCT sophos_pid), CHR(10)) AS sophos_pid_list,
    ARRAY_JOIN(ARRAY_AGG(DISTINCT parent_sophos_pid), CHR(10)) AS parent_sophos_pid_list,
    sha256,
    sha1,
    ml_score,
    pua_score,
    global_rep,
    local_rep,
    gid,
    uid,
    euid,
    egid
FROM
    full_list
GROUP BY
    user_name,
    parent_process_name,
    process_name,
    cmd_line,
    sha256,
    sha1,
    path,
    ml_score,
    pua_score,
    global_rep,
    local_rep,
    gid,
    uid,
    euid,
    egid,
    parent_path
ORDER BY last_seen DESC

# -*- coding: utf-8 -*-
"""Tests for JWTAuthMatrix.py. Run with tests/run_tests.sh (Jython 2.7, headless Swing)."""

import base64
import json
import re
import sys
import threading
import time
import unittest

from java.net import URL
from javax.swing import SwingUtilities

import JWTAuthMatrix as m


# --------------------------------------------------------------------------- fakes

def make_jwt(payload):
    def enc(obj):
        return base64.urlsafe_b64encode(json.dumps(obj)).rstrip("=")
    return "%s.%s.sig" % (enc({"alg": "HS256"}), enc(payload))


ALICE = make_jwt({"sub": "alice", "profile": {"role": "admin"}})
BOB = make_jwt({"sub": "bob"})
ANON = make_jwt({"iss": "x"})


class FakeService(object):
    def getHost(self):
        return "example.com"


class FakeMessage(object):
    def __init__(self, request, response="HTTP/1.1 200 OK\r\n\r\n"):
        self.request, self.response, self.service = request, response, FakeService()

    def getRequest(self):
        return self.request

    def getResponse(self):
        return self.response

    def getHttpService(self):
        return self.service


def request(path, *headers, **kwargs):
    method = kwargs.get("method", "GET")
    lines = ["%s %s HTTP/1.1" % (method, path), "Host: example.com"] + list(headers)
    return "\r\n".join(lines) + "\r\n\r\n" + kwargs.get("body", "")


def message(path, *headers, **kwargs):
    status = kwargs.pop("status", 200)
    return FakeMessage(request(path, *headers, **kwargs), "HTTP/1.1 %d X\r\n\r\n" % status)


class FakeRequestInfo(object):
    def __init__(self, raw):
        head, _, _ = raw.partition("\r\n\r\n")
        self.headers = head.split("\r\n")
        self.method, path = self.headers[0].split(" ")[:2]
        self.url = URL("https://example.com:443" + path)   # as Burp reports it
        self.body_offset = len(head) + 4

    def getHeaders(self):
        return self.headers

    def getMethod(self):
        return self.method

    def getUrl(self):
        return self.url

    def getBodyOffset(self):
        return self.body_offset


class FakeResponseInfo(object):
    def __init__(self, raw):
        self.status = int(raw.split(" ")[1])

    def getStatusCode(self):
        return self.status


class FakeHelpers(object):
    def analyzeRequest(self, msg):
        return FakeRequestInfo(msg.getRequest())

    def analyzeResponse(self, raw):
        return FakeResponseInfo(raw)

    def bytesToString(self, data):
        return data

    def buildHttpMessage(self, headers, body):
        return "\r\n".join(headers) + "\r\n\r\n" + body


class FakeCallbacks(object):
    TOOL_PROXY, TOOL_INTRUDER, TOOL_REPEATER = 4, 32, 64

    def __init__(self, saved=None):
        self.helpers = FakeHelpers()
        self.saved = dict(saved or {})
        self.history = []
        self.sent = []          # requests issued by replay
        self.persisted = []     # messages passed to saveBuffersToTempFiles
        self.status_for_token = {}
        self.delay = 0          # seconds makeHttpRequest blocks, to expose queueing bugs
        self.anonymous_status = None   # status for requests carrying no known token

    def getHelpers(self):
        return self.helpers

    def setExtensionName(self, name):
        pass

    def registerHttpListener(self, listener):
        pass

    def registerContextMenuFactory(self, factory):
        pass

    def registerExtensionStateListener(self, listener):
        pass

    def addSuiteTab(self, tab):
        self.tab = tab

    def saveExtensionSetting(self, key, value):
        self.saved[key] = value

    def loadExtensionSetting(self, key):
        return self.saved.get(key)

    def saveBuffersToTempFiles(self, msg):
        self.persisted.append(msg)
        return msg

    def getProxyHistory(self):
        return self.history

    def makeHttpRequest(self, service, raw):
        time.sleep(self.delay)
        self.sent.append(raw)
        for token, status in self.status_for_token.items():
            if token in raw:
                return FakeMessage(raw, "HTTP/1.1 %d X\r\n\r\n" % status)
        if self.anonymous_status and "Authorization:" not in raw:
            return FakeMessage(raw, "HTTP/1.1 %d X\r\n\r\n" % self.anonymous_status)
        return FakeMessage(raw, None)


def flush_edt():
    SwingUtilities.invokeAndWait(lambda: None)


def load_extension(callbacks=None):
    ext = m.BurpExtender()
    ext.registerExtenderCallbacks(callbacks or FakeCallbacks())
    return ext


def cell(view, row, col):
    return view.model.getValueAt(row, col)


# --------------------------------------------------------------------------- pure helpers

class EndpointTests(unittest.TestCase):
    def test_endpoint_key_includes_query_only_when_present(self):
        self.assertEqual(m.endpoint_key("GET", "/a", None), "GET /a")
        self.assertEqual(m.endpoint_key("POST", "/a", "x=1"), "POST /a?x=1")

    def test_group_endpoints_groups_query_variants_in_first_seen_order(self):
        groups = m.group_endpoints(["GET /b?x=1", "GET /a", "GET /b", "POST /a"])
        self.assertEqual(list(groups.items()), [
            ("GET /b", ["GET /b?x=1", "GET /b"]),
            ("GET /a", ["GET /a"]),
            ("POST /a", ["POST /a"]),
        ])


class TokenTests(unittest.TestCase):
    def test_extracts_bearer_token_case_insensitively(self):
        headers = ["GET / HTTP/1.1", "authorization: bearer abc.def.ghi"]
        self.assertEqual(m.extract_token(headers, m.LOCATION_AUTH, "jwt"), "abc.def.ghi")

    def test_ignores_non_bearer_authorization(self):
        self.assertIsNone(m.extract_token(["Authorization: Basic Zm9v"], m.LOCATION_AUTH, "jwt"))

    def test_extracts_named_cookie(self):
        headers = ["Cookie: a=1; jwt=tok; b=2"]
        self.assertEqual(m.extract_token(headers, m.LOCATION_COOKIE, "jwt"), "tok")
        self.assertIsNone(m.extract_token(headers, m.LOCATION_COOKIE, "session"))

    def test_replace_bearer_token(self):
        headers = ["GET / HTTP/1.1", "Authorization: Bearer old", "X: y"]
        self.assertEqual(m.replace_token(headers, "new", m.LOCATION_AUTH, "jwt"),
                         ["GET / HTTP/1.1", "Authorization: Bearer new", "X: y"])

    def test_replace_adds_missing_authorization_header(self):
        self.assertEqual(m.replace_token(["GET / HTTP/1.1"], "new", m.LOCATION_AUTH, "jwt"),
                         ["GET / HTTP/1.1", "Authorization: Bearer new"])

    def test_replace_cookie_keeps_other_cookies(self):
        headers = ["GET / HTTP/1.1", "Cookie: a=1;  jwt=old; flag"]
        self.assertEqual(m.replace_token(headers, "new", m.LOCATION_COOKIE, "jwt"),
                         ["GET / HTTP/1.1", "Cookie: a=1; jwt=new; flag"])

    def test_replace_cookie_appends_to_existing_cookie_header(self):
        headers = ["GET / HTTP/1.1", "Cookie: a=1"]
        self.assertEqual(m.replace_token(headers, "new", m.LOCATION_COOKIE, "jwt"),
                         ["GET / HTTP/1.1", "Cookie: a=1; jwt=new"])

    def test_no_token_removes_authorization_header(self):
        headers = ["GET / HTTP/1.1", "Authorization: Bearer old", "X: y"]
        self.assertEqual(m.replace_token(headers, None, m.LOCATION_AUTH, "jwt"),
                         ["GET / HTTP/1.1", "X: y"])

    def test_no_token_removes_cookie_and_empty_cookie_header(self):
        self.assertEqual(m.replace_token(["GET / HTTP/1.1", "Cookie: a=1; jwt=old"], None,
                                         m.LOCATION_COOKIE, "jwt"),
                         ["GET / HTTP/1.1", "Cookie: a=1"])
        self.assertEqual(m.replace_token(["GET / HTTP/1.1", "Cookie: jwt=old"], None,
                                         m.LOCATION_COOKIE, "jwt"),
                         ["GET / HTTP/1.1"])

    def test_replace_cookie_adds_cookie_header_when_absent(self):
        self.assertEqual(m.replace_token(["GET / HTTP/1.1"], "new", m.LOCATION_COOKIE, "jwt"),
                         ["GET / HTTP/1.1", "Cookie: jwt=new"])


class JwtClaimTests(unittest.TestCase):
    def test_reads_top_level_and_dotted_claims(self):
        self.assertEqual(m.jwt_claim(ALICE, "sub"), "alice")
        self.assertEqual(m.jwt_claim(ALICE, "profile.role"), "admin")

    def test_non_string_claims_are_stringified(self):
        self.assertEqual(m.jwt_claim(make_jwt({"id": 42}), "id"), "42")

    def test_missing_claim_or_garbage_token_returns_none(self):
        self.assertIsNone(m.jwt_claim(ALICE, "email"))
        self.assertIsNone(m.jwt_claim(ALICE, "sub.deeper"))
        self.assertIsNone(m.jwt_claim("not-a-jwt", "sub"))
        self.assertIsNone(m.jwt_claim("a.!!!.c", "sub"))


class CodeGroupTests(unittest.TestCase):
    GROUPS = list(m.DEFAULT_CODE_GROUPS)

    def pattern(self, codes, groups=None):
        group = m.pick_group(codes, groups or self.GROUPS)
        return group and group[0]

    def test_uniform_codes_pick_their_class(self):
        self.assertEqual(self.pattern(["200", "204"]), "2xx")
        self.assertEqual(self.pattern(["403"]), "4xx")

    def test_mixed_codes_fall_back_to_last_partially_matching_group(self):
        self.assertEqual(self.pattern(["200", "403"]), "4xx")

    def test_combined_pattern_wins_when_every_part_is_present(self):
        groups = self.GROUPS + [("2xx,5xx", 0x123456, "Mixed")]
        self.assertEqual(self.pattern(["200", "500"], groups), "2xx,5xx")

    def test_exact_code_pattern(self):
        self.assertEqual(self.pattern(["401"], [("401", 1, "Unauth")]), "401")

    def test_no_matching_group(self):
        self.assertIsNone(self.pattern(["101"]))

    def test_code_groups_round_trip_through_text(self):
        text = m.format_code_groups(self.GROUPS)
        self.assertEqual(m.parse_code_groups(text), (self.GROUPS, []))

    def test_parse_code_groups_reports_invalid_lines(self):
        groups, errors = m.parse_code_groups("2xx:#00ff00:OK\n\nbad line\n4xx:zz:Nope")
        self.assertEqual(groups, [("2xx", 0x00ff00, "OK")])
        self.assertEqual(len(errors), 2)


class ExportTests(unittest.TestCase):
    SNAPSHOT = (['GET /a"b'], ["alice", "bob"], {'GET /a"b': {"alice": {"200": 2, "403": 1}}})

    def test_csv_quotes_values_and_fills_empty_cells(self):
        self.assertEqual(m.matrix_to_csv(self.SNAPSHOT),
                         '"Endpoint","alice","bob"\n"GET /a""b","200: 2, 403: 1","0"')

    def test_json_shape(self):
        data = json.loads(m.matrix_to_json(self.SNAPSHOT, "sub"))
        self.assertEqual(data, {
            "jwt_field": "sub",
            "users": ["alice", "bob"],
            "endpoints": [{"endpoint": 'GET /a"b',
                           "users": {"alice": {"200": 2, "403": 1}, "bob": {}}}],
        })


class MatrixStoreTests(unittest.TestCase):
    def test_snapshot_counts_codes_in_first_seen_order(self):
        store = m.MatrixStore()
        store.add("GET /b", "bob", "403", "m1")
        store.add("GET /a", "alice", "200", "m2")
        store.add("GET /b", "bob", "403", "m3")
        store.add_user("carol")
        self.assertEqual(store.snapshot(), (
            ["GET /b", "GET /a"], ["bob", "alice", "carol"],
            {"GET /b": {"bob": {"403": 2}}, "GET /a": {"alice": {"200": 1}}}))
        self.assertEqual(store.messages(["GET /b"], "bob"), ["m1", "m3"])
        self.assertEqual(store.all_messages(), ["m1", "m3", "m2"])

    def test_remove_drops_endpoints_and_their_messages(self):
        store = m.MatrixStore()
        store.add("GET /a", "alice", "200", "m1")
        store.add("GET /b", "alice", "200", "m2")
        store.remove(["GET /a"])
        self.assertEqual(store.snapshot()[0], ["GET /b"])
        self.assertEqual(store.all_messages(), ["m2"])


class DuplicateTests(unittest.TestCase):
    def test_store_keeps_first_message_per_identity_within_each_cell(self):
        store = m.MatrixStore()
        store.add("GET /a", "alice", "200", "a1")
        store.add("GET /a", "alice", "500", "a1-again")
        store.add("GET /a", "bob", "200", "a1")          # other user: kept
        store.add("GET /a", "alice", "200", "a2")
        removed = store.remove_duplicates(lambda msg: msg.split("-")[0])
        self.assertEqual(removed, 1)
        self.assertEqual(store.messages(["GET /a"], "alice"), ["a1", "a2"])
        self.assertEqual(store.snapshot()[2], {"GET /a": {"alice": {"200": 2}, "bob": {"200": 1}}})


class TokenTableTests(unittest.TestCase):
    def test_upsert_updates_existing_user_and_tokens_skip_blank_rows(self):
        model = m.TokenTableModel()
        model.upsert("alice", "t1", "now")
        model.addRow(["", "", ""])
        model.upsert("bob", "t2", "now")
        model.upsert("alice", "t3", "later")
        self.assertEqual(model.getRowCount(), 3)
        self.assertEqual(list(model.tokens().items()), [("alice", "t3"), ("bob", "t2")])
        self.assertFalse(model.isCellEditable(0, 2))

    def test_anonymous_row_is_added_once_and_replays_without_token(self):
        model = m.TokenTableModel()
        model.upsert("alice", "t1", "now")
        model.add_anonymous()
        model.add_anonymous()
        self.assertEqual(model.getRowCount(), 2)
        self.assertEqual(list(model.tokens().items()), [("alice", "t1"), (m.ANONYMOUS_USER, None)])


# --------------------------------------------------------------------------- extension

class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.callbacks = FakeCallbacks()
        self.ext = load_extension(self.callbacks)

    def capture(self, msg, tool=FakeCallbacks.TOOL_PROXY):
        self.ext.processHttpMessage(tool, True, msg)   # request phase is ignored
        self.ext.processHttpMessage(tool, False, msg)
        flush_edt()
        flush_edt()

    def test_captures_bearer_requests_into_the_matrix(self):
        self.capture(message("/a", "Authorization: Bearer " + ALICE))
        self.capture(message("/a", "Authorization: Bearer " + BOB, status=403))
        self.capture(message("/a", "Authorization: Bearer " + ANON, status=401))
        self.capture(message("/a"))   # no token: ignored
        view = self.ext.matrix_view
        self.assertEqual([view.model.getColumnName(c) for c in range(view.model.getColumnCount())],
                         ["Endpoint", "alice", "bob", "<no-sub>"])
        self.assertEqual([cell(view, 0, c) for c in range(4)], ["GET /a", "200: 1", "403: 1", "401: 1"])
        self.assertEqual(len(self.callbacks.persisted), 3)
        self.assertEqual(list(self.ext.tokens.tokens().items()), [("alice", ALICE), ("bob", BOB)])

    def test_respects_tool_selection(self):
        self.ext.settings.listen_repeater = False
        self.capture(message("/a", "Authorization: Bearer " + ALICE), FakeCallbacks.TOOL_REPEATER)
        self.capture(message("/b", "Authorization: Bearer " + ALICE), 1024)   # Extender traffic
        self.assertEqual(self.ext.captured.snapshot()[0], [])

    def test_cookie_location(self):
        self.ext.settings.location = m.LOCATION_COOKIE
        self.ext.settings.cookie_name = "session"
        self.capture(message("/a", "Cookie: session=" + ALICE))
        self.capture(message("/b", "Authorization: Bearer " + BOB))
        self.assertEqual(self.ext.captured.snapshot()[:2], (["GET /a"], ["alice"]))

    def test_query_variants_expand_under_base_row_and_can_be_deleted(self):
        self.capture(message("/a", "Authorization: Bearer " + ALICE))
        self.capture(message("/a?x=1", "Authorization: Bearer " + ALICE, status=403))
        self.capture(message("/b", "Authorization: Bearer " + ALICE))
        view = self.ext.matrix_view
        self.assertEqual([cell(view, r, 0) for r in range(view.model.getRowCount())],
                         ["[+] GET /a", "GET /b"])
        self.assertEqual(cell(view, 0, 1), "200: 1, 403: 1")
        self.assertTrue(view.model.toggle(0))
        self.assertFalse(view.model.toggle(3))   # child row
        self.assertEqual([cell(view, r, 0) for r in range(4)],
                         ["[-] GET /a", "    GET /a", "    GET /a?x=1", "GET /b"])
        self.assertEqual(cell(view, 2, 1), "403: 1")
        doomed = view.endpoints_for_rows([2, 3])
        self.capture(message("/0", "Authorization: Bearer " + ALICE))   # rows shift meanwhile
        view.delete_endpoints(doomed)
        self.assertEqual(self.ext.captured.snapshot()[0], ["GET /a", "GET /0"])

    def test_remove_duplicates_per_user_by_method_url_and_body(self):
        auth = "Authorization: Bearer "
        for msg in [message("/a?x=1", auth + ALICE), message("/a?x=1", auth + ALICE, status=403),
                    message("/a?x=2", auth + ALICE),
                    message("/a?x=1", auth + BOB),
                    message("/p", auth + ALICE, method="POST", body="id=1"),
                    message("/p", auth + ALICE, method="POST", body="id=1"),
                    message("/p", auth + ALICE, method="POST", body="id=2")]:
            self.capture(msg)
        done = threading.Event()
        self.ext.remove_duplicates(on_done=done.set)
        self.assertTrue(done.wait(10))
        self.assertEqual(self.ext.captured.snapshot()[2], {
            "GET /a?x=1": {"alice": {"200": 1}, "bob": {"200": 1}},
            "GET /a?x=2": {"alice": {"200": 1}},
            "POST /p": {"alice": {"200": 2}},
        })
        self.assertEqual(cell(self.ext.matrix_view, 0, 1), "200: 2")   # view refreshed

    def test_send_to_matrix_skips_bad_messages(self):
        class Broken(FakeMessage):
            def getRequest(self):
                raise ValueError("unreadable")
        done = threading.Event()
        self.ext.send_to_matrix([Broken("x"), message("/a", "Authorization: Bearer " + ALICE)],
                                on_done=done.set)
        self.assertTrue(done.wait(10))
        self.assertEqual(self.ext.captured.snapshot()[0], ["GET /a"])

    def test_header_sort_cycles_and_keeps_variants_under_their_endpoint(self):
        auth = "Authorization: Bearer "
        self.capture(message("/b", auth + ALICE, status=403))
        self.capture(message("/a?x=2", auth + ALICE))
        self.capture(message("/a?x=1", auth + ALICE, status=500))
        self.capture(message("/C", auth + ALICE))
        view, model = self.ext.matrix_view, self.ext.matrix_view.model
        model.toggle(1)   # expand GET /a

        def labels():
            return [cell(view, r, 0).strip() for r in range(model.getRowCount())]

        self.assertEqual(labels(), ["GET /b", "[-] GET /a", "GET /a?x=2", "GET /a?x=1", "GET /C"])
        view.toggle_sort(0)
        self.assertEqual(labels(), ["[-] GET /a", "GET /a?x=1", "GET /a?x=2", "GET /b", "GET /C"])
        self.assertEqual(view.table.getColumnModel().getColumn(0).getHeaderValue(),
                         u"Endpoint \u25b2")
        view.toggle_sort(0)
        self.assertEqual(labels(), ["GET /C", "GET /b", "[-] GET /a", "GET /a?x=2", "GET /a?x=1"])
        view.toggle_sort(1)   # alice: by status codes, then counts
        self.assertEqual(labels(), ["GET /C", "[-] GET /a", "GET /a?x=2", "GET /a?x=1", "GET /b"])
        self.assertEqual(view.table.getColumnModel().getColumn(0).getHeaderValue(), "Endpoint")
        view.toggle_sort(1)
        view.toggle_sort(1)   # third click: back to capture order
        self.assertEqual(labels(), ["GET /b", "[-] GET /a", "GET /a?x=2", "GET /a?x=1", "GET /C"])
        self.assertEqual(view.table.getColumnModel().getColumn(1).getHeaderValue(), "alice")

    def test_sort_survives_live_updates(self):
        auth = "Authorization: Bearer "
        self.capture(message("/b", auth + ALICE))
        self.ext.matrix_view.toggle_sort(0)
        self.capture(message("/a", auth + ALICE))
        self.assertEqual(cell(self.ext.matrix_view, 0, 0), "GET /a")

    def test_import_proxy_history_rebuilds_matrix_with_url_filter(self):
        self.capture(message("/old", "Authorization: Bearer " + ALICE))
        self.callbacks.history = [message("/api/x", "Authorization: Bearer " + ALICE),
                                  message("/static/y", "Authorization: Bearer " + ALICE),
                                  FakeMessage(request("/api/z", "Authorization: Bearer " + BOB), None)]
        done = threading.Event()
        self.ext.import_history(re.compile("^https://example.com/api/"), on_done=done.set)
        self.assertTrue(done.wait(10))
        self.assertEqual(self.ext.captured.snapshot()[0], ["GET /api/x"])


class ReplayTests(unittest.TestCase):
    def test_replays_every_request_with_every_token(self):
        callbacks = FakeCallbacks()
        callbacks.status_for_token = {ALICE: 200, BOB: 403}
        callbacks.delay = 0.05   # tasks queue up behind a single thread
        store = m.MatrixStore()
        messages = [message("/a", "Authorization: Bearer " + ANON),
                    message("/b", "X: 1", method="POST", body="payload")]
        progress = []
        finished = threading.Event()
        job = m.ReplayJob(callbacks, store, messages,
                          m.OrderedDict([("alice", ALICE), ("bob", BOB), ("carol", "dead")]),
                          m.LOCATION_AUTH, "jwt", 1,
                          on_progress=lambda done, total: progress.append((done, total)),
                          on_finished=lambda cancelled: finished.set())
        job.start()
        self.assertTrue(finished.wait(10))
        flush_edt()
        endpoints, users, counts = store.snapshot()
        self.assertEqual(sorted(endpoints), ["GET /a", "POST /b"])
        self.assertEqual(users, ["alice", "bob", "carol"])
        self.assertEqual(counts["GET /a"], {"alice": {"200": 1}, "bob": {"403": 1}})
        self.assertEqual(counts["POST /b"], {"alice": {"200": 1}, "bob": {"403": 1}})
        self.assertEqual(sorted(raw.split(" HTTP")[0] for raw in callbacks.sent),
                         ["GET /a"] * 3 + ["POST /b"] * 3)
        self.assertTrue(all(raw.count("Authorization:") == 1 for raw in callbacks.sent))
        self.assertTrue(any(raw.endswith("\r\n\r\npayload") and BOB in raw for raw in callbacks.sent))
        self.assertEqual(max(progress), (6, 6))


    def test_anonymous_user_replays_without_authorization(self):
        callbacks = FakeCallbacks()
        callbacks.anonymous_status = 401
        store = m.MatrixStore()
        finished = threading.Event()
        job = m.ReplayJob(callbacks, store, [message("/a", "Authorization: Bearer " + ALICE)],
                          m.OrderedDict([(m.ANONYMOUS_USER, None)]), m.LOCATION_AUTH, "jwt", 1,
                          on_progress=lambda done, total: None,
                          on_finished=lambda cancelled: finished.set())
        job.start()
        self.assertTrue(finished.wait(10))
        self.assertEqual(store.snapshot()[2], {"GET /a": {m.ANONYMOUS_USER: {"401": 1}}})
        self.assertNotIn("Authorization:", callbacks.sent[0])

    def test_cancel_stops_pending_requests(self):
        callbacks = FakeCallbacks()
        callbacks.delay = 0.1
        messages = [message("/r%d" % i, "Authorization: Bearer " + ANON) for i in range(20)]
        result = []
        finished = threading.Event()
        job = m.ReplayJob(callbacks, m.MatrixStore(), messages, m.OrderedDict([("alice", ALICE)]),
                          m.LOCATION_AUTH, "jwt", 2, on_progress=lambda done, total: None,
                          on_finished=lambda cancelled: (result.append(cancelled), finished.set()))
        job.start()
        time.sleep(0.05)
        job.cancel()
        self.assertTrue(finished.wait(10))
        self.assertEqual(result, [True])
        sent_at_finish = len(callbacks.sent)
        time.sleep(0.3)
        self.assertEqual(len(callbacks.sent), sent_at_finish)   # nothing still in flight
        self.assertTrue(sent_at_finish < 10, sent_at_finish)


class SettingsTests(unittest.TestCase):
    def test_settings_persist_across_reloads(self):
        callbacks = FakeCallbacks()
        ext = load_extension(callbacks)
        ext.settings.user_claim = "email"
        ext.settings.code_groups = [("401", 0xabcdef, "Unauth")]
        ext.settings.save()
        reloaded = load_extension(FakeCallbacks(callbacks.saved))
        self.assertEqual(reloaded.settings.user_claim, "email")
        self.assertEqual(reloaded.settings.code_groups, [("401", 0xabcdef, "Unauth")])

    def test_corrupt_settings_fall_back_to_defaults(self):
        ext = load_extension(FakeCallbacks({"settings": '{"code_groups": [["2xx"]], "user_claim": 3}'}))
        self.assertEqual(ext.settings.code_groups, list(m.DEFAULT_CODE_GROUPS))
        self.assertEqual(ext.settings.user_claim, "sub")


if __name__ == "__main__":
    result = unittest.main(exit=False, verbosity=1).result
    sys.exit(0 if result.wasSuccessful() else 1)

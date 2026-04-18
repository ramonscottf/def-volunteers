-- Seed the three active DEF volunteer events
-- Run AFTER schema.sql

INSERT OR REPLACE INTO events (slug, name, tagline, event_date, venue, signup_url, accent_color, display_order, capacity, config, active, show_on_hub) VALUES
  ('gala-2026',
   'DEF Gala 2026',
   'A night of celebration supporting Davis County students',
   '2026-06-10',
   'Megaplex Theatres at Legacy Crossing',
   '/volunteer/gala',
   '#CB262C',
   1,
   NULL,
   '{"roles":["greeter","bar","coat_check","checkin","silent_auction","live_auction","teardown"],"shifts":["setup","event","teardown","full_evening"]}',
   1, 1),

  ('forekids-2026',
   'ForeKids Golf Classic 2026',
   'Monday, August 31 at Oakridge Country Club — supporting Davis County students',
   '2026-08-31',
   'Oakridge Country Club',
   '/volunteer/forekids',
   '#1b7d3a',
   2,
   152,
   '{"roles":["registration","player_packages","prize_table","breakfast","brunch","hole_spotter","contest_judge","photography","setup"],"shifts":["early_setup","registration","tournament","brunch","full_day"],"schedule":{"registration":"7:00 AM","shotgun_start":"8:00 AM"}}',
   1, 1),

  ('child-spree-2026',
   'Child Spree 2026',
   'Back-to-school shopping event for Davis County students in need',
   '2026-08-07',
   'Kohl''s Layton, Centerville, and Clinton',
   '/volunteer/child-spree',
   '#e84e8a',
   3,
   NULL,
   '{"roles":["shopper","ops","checkin","checkout"],"locations":{"layton":{"name":"Kohl''s Layton","address":"881 W Antelope Dr","cap":200,"ops_cap":8},"centerville":{"name":"Kohl''s Centerville","address":"510 N 400 W","cap":175,"ops_cap":8},"clinton":{"name":"Kohl''s Clinton","address":"1526 N 2000 W","cap":200,"ops_cap":10}}}',
   1, 1);

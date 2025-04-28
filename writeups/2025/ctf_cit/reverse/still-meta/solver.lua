local ok, result = pcall(dofile, "stillmeta.lua")
if not ok then
  print("Error loading stillmeta.lua: " .. result)
  return
end

for k, v in pairs(_G) do
  if type(v) == "string" and v:find("CIT{") then
    print(k .. ": " .. v)
  end
end

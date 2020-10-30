import React, {
  createContext,
  useCallback,
  useContext,
  useState,
} from "react";

const Auth = createContext();

const AuthProvider = ({ user, authenticated, children }) => {
  const [auth, setAuth] = useState({ user, authenticated });

  // eslint-disable-next-line no-return-assign
  const logout = useCallback(() => (window.location.href = "/api/logout"), []);
  // eslint-disable-next-line no-return-assign
  const login = useCallback(() => (window.location.href = "/api/login"), []);

  return (
    <Auth.Provider value={{ auth, setAuth, logout, login }}>
      {children}
    </Auth.Provider>
  );
};

const useAuthProvider = () => {
  const context = useContext(Auth);

  if (context === undefined) {
    throw new Error("There doesn't appear to be a provider.");
  }
  return context;
};

export { AuthProvider, useAuthProvider };

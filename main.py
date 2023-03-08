from intercept_packages.intercept_package import sniff_all


def main():
    while 1:
        try:
            sniff_all()
        except Exception:
            pass


if __name__ == '__main__':
    main()
